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

#pragma once
#ifndef _ENCRYPTION_H_
#define _ENCRYPTION_H_

#include <sgx_urts.h>
#include <sgx_tcrypto.h>
#include "nrt_tke.h"
#include "ra_quote.h"

#define TIMESOURCE_CHANGED    0xF001
#define TIMESTAMP_UNEXPECTED  0xF002
#define ATTEMPT_BACKOFF       0xF003

#define DH_PUBKEY_LENGTH 64
#define SALT_LENGTH 8

sgx_status_t create_enclave(const char* filename, sgx_enclave_id_t *eid);
sgx_status_t enclave_init(sgx_enclave_id_t eid, uint8_t* sealed_buf, uint32_t sealed_buf_size);
sgx_status_t enclave_init_ra(sgx_enclave_id_t eid, nrt_ra_context_t *context);
sgx_status_t enclave_process(sgx_enclave_id_t eid,
                             nrt_ra_context_t context,
                             const char *password,
                             sgx_cmac_128bit_tag_t *tag_cmac);
sgx_status_t obtain_quote(sgx_enclave_id_t eid, nrt_ra_context_t context, uint8_t* quote);

void print_quote( quote_t *p_isv_quote );

#endif
