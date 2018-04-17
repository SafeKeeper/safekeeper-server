/* Copyright (c) 2018 Aalto University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdarg.h>
#include <stdio.h>
#include <cstring>
#include <cassert>
#include <map>
#include <vector>

#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_report.h"
#include "sgx_thread.h"
#include "sgx_tae_service.h"
#include "sgx_spinlock.h"
#include "nrt_tke.h"
#include "safekeeper.h"
#include "enclave_t.h"

typedef std::string pswd_salt_t;

static std::map<pswd_salt_t, uint32_t> g_attempts_map;
static sgx_spinlock_t g_attempts_map_lock = SGX_SPINLOCK_INITIALIZER;

sgx_cmac_128bit_key_t g_key = {0x0};
bool initialized = false;
sgx_cmac_128bit_tag_t g_tag;

sgx_thread_mutex_t g_mutex = SGX_THREAD_MUTEX_INITIALIZER;

static sgx_time_source_nonce_t g_time_nonce_initial;

// The time when the next bump to the number of attempts happens
static sgx_time_t g_next_update_time;

// The interval at which updates to the number of attempts happen
const static sgx_time_t g_update_interval = 10; //...seconds

// The initial number of attempts given to each user
const static int g_initial_attempts = 10;

#define SGX_MISCSEL_EXINFO     0x00000001  /* report #PF and #GP inside enclave */
#define TSEAL_DEFAULT_MISCMASK (~SGX_MISCSEL_EXINFO)

// Serialization of internal state
static int serialize_key_attempts_map(uint8_t* buf, uint32_t* buf_len)
{
    const uint32_t required_len = sizeof(sgx_cmac_128bit_key_t) +
            (SALT_LENGTH + sizeof(uint32_t)) * g_attempts_map.size();

    if( buf == NULL ) {
        *buf_len = required_len;
        return 0;
    }

    if( *buf_len < required_len )
        return SGX_ERROR_INVALID_PARAMETER;

    memset(buf, 0, (size_t)*buf_len);
    memcpy(buf, g_key, sizeof(sgx_cmac_128bit_key_t));

    uint32_t buf_pos = sizeof(sgx_cmac_128bit_key_t);
    for( std::map<pswd_salt_t, uint32_t>::iterator it = g_attempts_map.begin();
         it != g_attempts_map.end(), buf_pos < *buf_len;
         ++it, buf_pos += SALT_LENGTH + sizeof(uint32_t) ) {

        pswd_salt_t salt = it->first;
        uint32_t attempts = it->second;
        const char* c_salt = salt.c_str();
        memcpy(&buf[buf_pos], salt.c_str(), strlen(c_salt));
        memcpy(&buf[buf_pos + SALT_LENGTH], &attempts, sizeof(uint32_t));
    }
    return 0;
}

// Deserialization of internal state
static int deserialize_key_attempts_map(uint8_t* buf, uint32_t buf_len)
{
    if( buf_len < sizeof(sgx_cmac_128bit_key_t) )
        return SGX_ERROR_INVALID_PARAMETER;

    memcpy(g_key, buf, sizeof(sgx_cmac_128bit_key_t));
    pswd_salt_t salt;
    for( uint32_t buf_pos = sizeof(sgx_cmac_128bit_key_t); buf_pos < buf_len;
         buf_pos += SALT_LENGTH + sizeof(uint32_t) ) {

        salt.assign( (char*)(buf + buf_pos), SALT_LENGTH );
        g_attempts_map[salt] = *(uint32_t*) &buf[buf_pos + SALT_LENGTH];

    }
    return 0;
}

// Attestation requires key derivation
// shared key is 32 bytes in little endian
// Feed SHA with its hex representation
sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
    uint16_t kdf_id,
    sgx_ec_key_128bit_t* smk_key,
    sgx_ec_key_128bit_t* sk_key,
    sgx_ec_key_128bit_t* mk_key,
    sgx_ec_key_128bit_t* vk_key)
{
    sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_sha_state_handle_t sha_context;
    sgx_sha256_hash_t key_material;
    const char *hex = "0123456789abcdef";
    uint8_t hash_buffer[2*sizeof(sgx_ec256_dh_shared_t)];

    if( NULL == shared_key )
        return SGX_ERROR_INVALID_PARAMETER;

    for( int i = 0; i < sizeof(sgx_ec256_dh_shared_t); i++ ) {
        hash_buffer[ 2*i ]     = hex[ shared_key->s[i] / 16 ];
        hash_buffer[ 2*i + 1 ] = hex[ shared_key->s[i] % 16 ];
    }
    // memcpy(hash_buffer, shared_key, sizeof(sgx_ec256_dh_shared_t));

    sgx_ret = sgx_sha256_init(&sha_context);
    if( sgx_ret != SGX_SUCCESS )
        return sgx_ret;

    sgx_ret = sgx_sha256_update(hash_buffer, sizeof(hash_buffer), sha_context);
    if( sgx_ret != SGX_SUCCESS ) {
        sgx_sha256_close(sha_context);
        return sgx_ret;
    }

    sgx_ret = sgx_sha256_get_hash(sha_context, &key_material);
    if( sgx_ret != SGX_SUCCESS ) {
        sgx_sha256_close(sha_context);
        return sgx_ret;
    }
    sgx_sha256_close(sha_context);

    memcpy(sk_key, key_material, sizeof(sgx_ec_key_128bit_t));
    memset(key_material, 0, sizeof(sgx_sha256_hash_t));

    return SGX_SUCCESS;
}

// Attestation
int ecall_enclave_init_ra( int b_pse, nrt_ra_context_t *p_context )
{
    sgx_status_t ret;
    if( b_pse ) {
        int busy_retry = 2;
        do {
            ret = sgx_create_pse_session();
        } while( ret == SGX_ERROR_BUSY && busy_retry-- );

        if( ret != SGX_SUCCESS )
            return ret;
    }
    ret = nrt_ra_init_ex( b_pse, key_derivation, p_context );
    if( b_pse ) {
        sgx_close_pse_session();
    }
    return ret;
}

int ecall_enclave_close_ra( nrt_ra_context_t context )
{
    sgx_status_t ret;
    ret = nrt_ra_close( context );
    return ret;
}

// Enclave API
// Unseals the key and the attempts database
// If size_sdata is 0, generates a new key
int ecall_enclave_init(const uint8_t *sealed_input, uint32_t size_sdata)
{
    uint32_t buf_len;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint8_t *buf;

    if( initialized )
        return SGX_SUCCESS;

    if( size_sdata != 0 ) {

        // Note that this should be enough for unseal
        buf = (uint8_t*)malloc(size_sdata);

        ret = sgx_unseal_data((sgx_sealed_data_t*)sealed_input, NULL, NULL, buf, &buf_len);
        if( ret != SGX_SUCCESS ) {
            free(buf);
            return ret;
        }

        ret = (sgx_status_t)deserialize_key_attempts_map(buf, buf_len);
        free(buf);
        if( ret != SGX_SUCCESS ) {
            return ret;
        }

    } else {
        // Generate a random key
        ret = sgx_read_rand(g_key, sizeof(sgx_cmac_128bit_key_t));
        if( ret != SGX_SUCCESS ) {
            return ret;
        }
    }

    // Initialize the time nonce
    // Create a session with PSE
    sgx_time_t current_time;
    int busy_retry_times = 2;
    do {
        ret = sgx_create_pse_session();
    } while( ret == SGX_ERROR_BUSY && busy_retry_times-- );
    if( ret != SGX_SUCCESS ) {
        return ret;
    }

    ret = sgx_get_trusted_time(&current_time, &g_time_nonce_initial);
    g_next_update_time = current_time + g_update_interval;
    sgx_close_pse_session();

    if( ret != SGX_SUCCESS )
    {
        return ret;
    }

    initialized = true;

    return SGX_SUCCESS;
}

int ecall_reset_attempts()
{
    sgx_time_t current_time;
    sgx_time_source_nonce_t time_nonce;
    bool update_time_passed = false;
    uint32_t ret;

    if( !initialized ) {
        return SGX_ERROR_UNEXPECTED;
    }

    // Create a session with PSE
    int busy_retry_times = 2;
    do {
        ret = sgx_create_pse_session();
    } while( ret == SGX_ERROR_BUSY && busy_retry_times-- );
    if( ret != SGX_SUCCESS ) {
        return ret;
    }

    ret = sgx_get_trusted_time(&current_time, &time_nonce);
    sgx_close_pse_session();

    if( ret != SGX_SUCCESS )
    {
        switch(ret)
        {
        case SGX_ERROR_SERVICE_UNAVAILABLE:
            /* Architecture Enclave Service Manager is not installed or not
               working properly.*/
            break;
        case SGX_ERROR_SERVICE_TIMEOUT:
            /* Retry the operation */
            break;
        case SGX_ERROR_BUSY:
            /* Retry the operation later */
            break;
        default:
            /* Other errors */
            break;
        }
        return ret;
    }

    /* Source nonce must be the same, otherwise time source is changed and
       the two timestamps are not comparable. */
    if (memcmp(&time_nonce, &g_time_nonce_initial,
        sizeof(sgx_time_source_nonce_t)))
    {
        ret  = TIMESOURCE_CHANGED;
        return ret;
    }

    // Check if the number of attempts should be increased
    if( current_time > g_next_update_time ) {
        sgx_spin_lock(&g_attempts_map_lock);
        for (std::map<pswd_salt_t, uint32_t>::iterator it = g_attempts_map.begin();
             it != g_attempts_map.end(); ++it)
            it->second = g_initial_attempts;
        sgx_spin_unlock(&g_attempts_map_lock);
    }

    return SGX_SUCCESS;
}

int ecall_process(nrt_ra_context_t context,
        const char *password, uint32_t password_length,
        sgx_cmac_128bit_tag_t *tag_cmac)
{
    sgx_status_t status;
    uint32_t ret;
    pswd_salt_t salt;
    uint8_t *pass;
    bool encrypted = false;

    if( !initialized ) {
        return SGX_ERROR_UNEXPECTED;
    }

    if( password_length < SALT_LENGTH ) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    salt.assign( &password[password_length - SALT_LENGTH], SALT_LENGTH );
    password_length -= SALT_LENGTH;

    // Check if the password is encrypted
    if( password_length > DH_PUBKEY_LENGTH ) {
        encrypted = true;
        ret = nrt_ra_set_gb_trusted(context,
            (sgx_ec256_public_t*)(&password[password_length - DH_PUBKEY_LENGTH]));
        if( ret != SGX_SUCCESS )
            return ret;

        password_length -= DH_PUBKEY_LENGTH;
    }

    pass = (uint8_t*)malloc(password_length);
    memcpy( pass, password, password_length );

    // Decrypt if necessary
    if( encrypted ) {
        sgx_ra_key_128_t sk_key;
        ret = nrt_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if( ret != SGX_SUCCESS )
            return ret;

        uint8_t aes_ctr[16] = {0};
        aes_ctr[15] = 1;
        ret = sgx_aes_ctr_decrypt(&sk_key, (const uint8_t*)password, password_length,
                                  aes_ctr, 128, pass);
    }

    // Check if the salt was already seen
    sgx_spin_lock(&g_attempts_map_lock);

    std::map<pswd_salt_t, uint32_t>::iterator it = g_attempts_map.find( salt );
    if( it == g_attempts_map.end() ) {
        // Haven't seen this salt before, lets add to the map
        g_attempts_map[salt] = g_initial_attempts;
    } else {
        // Found the salt, check if the number of attempts greater than zero */
        if(it->second == 0)
        {
            ret = ATTEMPT_BACKOFF;
            print_string_ocall("\nThe attempt is blocked\n");
            sgx_spin_unlock(&g_attempts_map_lock);
            return ret;
        }

        // Not blocked, so decrease the number of attempts
        it->second--;
    }
    sgx_spin_unlock(&g_attempts_map_lock);

    status = sgx_rijndael128_cmac_msg(&g_key, pass, password_length, tag_cmac);

    return status;
}

int ecall_shutdown(uint8_t *sealed_output, uint32_t *size_sdata)
{
    uint32_t input_len, sealed_len;
    uint8_t *input, *sealed;

    sgx_spin_lock(&g_attempts_map_lock);

    initialized = false;
    serialize_key_attempts_map(NULL, &input_len);

    sgx_spin_unlock(&g_attempts_map_lock);

    sealed_len = sgx_calc_sealed_data_size(0, input_len);

    if( sealed_len > *size_sdata )
        return SGX_ERROR_INVALID_PARAMETER;

    if( sealed_output == NULL ) {
        *size_sdata = sealed_len;
        return SGX_SUCCESS;
    }

    input = (uint8_t*)malloc(input_len);
    sealed = (uint8_t*)malloc(sealed_len);

    serialize_key_attempts_map(input, &input_len);

    sgx_attributes_t attribute_mask;
    attribute_mask.flags = SGX_FLAGS_RESERVED | SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG;
    attribute_mask.xfrm = 0x0;

    if (sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE,
                       attribute_mask,
                       TSEAL_DEFAULT_MISCMASK, 0, NULL,
                       input_len, input, sealed_len,
                       (sgx_sealed_data_t *) sealed))
        return SGX_ERROR_UNEXPECTED;

    memcpy(sealed_output, sealed, sealed_len);
    free(sealed);
    free(input);

    return SGX_SUCCESS;
}
