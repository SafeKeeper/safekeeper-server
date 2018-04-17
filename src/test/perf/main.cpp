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

#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <string>
#include <fstream>
#include <iostream>
#include <ctime>
#include <sys/time.h>
#include <thread>
#include <mutex>
#include <fcntl.h>

#define MAX_PATH FILENAME_MAX

#define BUFFERSIZE 8192
#include <b64/encode.h>

#include <sgx_urts.h>
#include <pthread.h>
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include "sgx_trts.h"
#include "safekeeper.h"

#include "enclave_u.h"

#include "sgx_errors.h"

//std::mutex try_mutex;
//rwlock_t lock_eid;

sgx_cmac_128bit_tag_t tag_cmac = {0};
uint8_t sealed_key[1024] = {0};

#define ENCLAVE_FILENAME "build/enclave/enclave.signed.so"

/* OCall functions */
sgx_status_t ocall_write(const uint8_t *buf, int32_t buflen)
{
    for( int i = 0; i < buflen; i++ ){
        printf("%#01x ", buf[i]);
    }

    return SGX_SUCCESS;
}

void print_string_ocall(const char *str)
{
    printf("%s", str);
}

static int create_init_enclave(sgx_enclave_id_t *eid, nrt_ra_context_t *ra_context)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Create and initialize the enclave */
    if(( ret = create_enclave(ENCLAVE_FILENAME, eid) ) != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    std::cout << "Initializing the enclave key...";
    if(( ret = enclave_init(*eid, NULL, 0) ) != SGX_SUCCESS){
        print_error_message(ret);
        return -1;
    }
    std::cout << " success." << std::endl;
    std::cout << "Initializing the enclave remote attestation...";
    if(( ret = enclave_init_ra(*eid, ra_context) ) != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    std::cout << " success." << std::endl;

    return 0;
}

static int rate_limit_test(sgx_enclave_id_t eid, nrt_ra_context_t ra_context)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    const char* password = "Pass_Salt12345678910ABCDEF";
    // Test rate-limiting, attempt to encrypt several times
    std::cout << std::endl << "Testing rate limiting" << std::endl;
    for( int i = 0; i < 12; i++ ) {
        ret = enclave_process(eid, ra_context, password, &tag_cmac);
        if (ret != SGX_SUCCESS) {
            print_error_message(ret);
        }
    }

    return 0;
}

static int performance_test(sgx_enclave_id_t eid, nrt_ra_context_t ra_context)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    // Test performance, attempt to encrypt a lot
    std::cout << std::endl << "Preparing passwords" << std::endl;
    #define PASS_NUM 1000000
    #define PASS_SALT_LEN 24
    char *pass = (char*)malloc( PASS_SALT_LEN*PASS_NUM );
    memset(pass, 0, PASS_SALT_LEN*PASS_NUM);
    if( pass == NULL ) {
        std::cout << "Error: could not allocate memory for passwords\n" << std::endl;
        return -1;
    }

    int fd = open("/dev/urandom", O_RDONLY);
    std::cout << std::endl << "Random passwords generating..." << std::endl;
    for( int i = 0; i < PASS_NUM*PASS_SALT_LEN; i+=PASS_SALT_LEN ) {
        do {
            read(fd, pass+i, PASS_SALT_LEN - 1);
            for( int j = 0; j < PASS_SALT_LEN; j++ )
                pass[i + j] = 48 + (pass[i + j] % 48);
            pass[i + PASS_SALT_LEN - 1] = '\0';
        } while( strlen(&pass[i]) < (PASS_SALT_LEN-1) );
    }

    std::cout << std::endl << "Testing encryption time" << std::endl;
    clock_t p_start = clock();
    for( int i = 0; i < PASS_NUM*PASS_SALT_LEN; i+=PASS_SALT_LEN ) {
        //printf("%d ", i);
        ret = enclave_process(eid, ra_context, &pass[i], &tag_cmac);
        //std::cout << std::endl << "Password: " << &pass[i] << std::endl;
        if (ret != SGX_SUCCESS) {
            printf("Error at encrypting password number %d\n", i/PASS_SALT_LEN);
            print_error_message(ret);
            if( ret == ATTEMPT_BACKOFF ) continue;
            free(pass);
            return -1;
        }
    }
    clock_t p_time = (double) ( clock() - p_start ) / CLOCKS_PER_SEC * 1000.0;
    std::cout << std::endl << PASS_NUM << " calls to process() are: " << p_time << " ms" << std::endl;

    std::cout << std::endl << "Testing second round encryption time" << std::endl;
    p_start = clock();
    for( int i = 0; i < PASS_NUM*PASS_SALT_LEN; i+=PASS_SALT_LEN ) {
        //printf("%d ", i);
        ret = enclave_process(eid, ra_context, &pass[i], &tag_cmac);
        //std::cout << std::endl << "Password: " << &pass[i] << std::endl;
        if (ret != SGX_SUCCESS) {
            printf("Error at encrypting password number %d\n", i/PASS_SALT_LEN);
            print_error_message(ret);
            if( ret == ATTEMPT_BACKOFF ) continue;
            free(pass);
            return -1;
        }
    }
    p_time = (double) ( clock() - p_start ) / CLOCKS_PER_SEC * 1000.0;
    std::cout << std::endl << PASS_NUM << " calls to process() are: " << p_time << " ms" << std::endl;

    free(pass);

    return 0;
}

#ifndef QUOTE_SIZE
#define QUOTE_SIZE 1116
#endif

static int ra_test(sgx_enclave_id_t eid, nrt_ra_context_t ra_context)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint8_t quote[QUOTE_SIZE];
    char encoded_quote[(QUOTE_SIZE*2) + 4] = {0};

    ret = obtain_quote(eid, ra_context, quote);

    if (ret != SGX_SUCCESS) {
        printf("Error at getting the quote.\n");
        print_error_message(ret);
        return -1;
    }

    printf("Got the quote, encoding it in b64.\n");
    base64::encoder b64enc;
    memset( &b64enc, 0, sizeof(b64enc) );
    b64enc.encode( (const char*)quote, QUOTE_SIZE, encoded_quote );
    printf("%s\n", encoded_quote);

    return 0;
}

int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    sgx_enclave_id_t eid = 0;
    nrt_ra_context_t ra_context;

    create_init_enclave(&eid, &ra_context);

    rate_limit_test(eid, ra_context);
    performance_test(eid, ra_context);
    ra_test(eid, ra_context);

    sgx_destroy_enclave(eid);

    return 0;
}
