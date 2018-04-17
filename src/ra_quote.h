/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.

 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 2018 Aalto University
 *  
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *  http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _RA_QUOTE_H
#define _RA_QUOTE_H
 
#define ISVSVN_SIZE         2
#define PSDA_SVN_SIZE       4
#define GID_SIZE            4
#define PSVN_SIZE           18

#define HASH_SIZE    32  // SHA256
#define MAC_SIZE     16  // Message Authentication Code
                         // - 16 bytes

#define REPORT_DATA_SIZE         64

typedef uint8_t             measurement_t[HASH_SIZE];
typedef uint8_t             mac_t[MAC_SIZE];
typedef uint8_t             report_data_t[REPORT_DATA_SIZE];
typedef uint16_t            prod_id_t;

#define CPUSVN_SIZE  16

typedef uint8_t             cpu_svn_t[CPUSVN_SIZE];
typedef uint16_t            isv_svn_t;

typedef struct attributes_t
{
    uint64_t                flags;
    uint64_t                xfrm;
} attributes_t;

typedef struct report_body_t {
    cpu_svn_t        cpu_svn;        // (  0) Security Version of the CPU
    uint8_t          reserved1[32];  // ( 16)
    attributes_t     attributes;     // ( 48) Any special Capabilities
                                     //       the Enclave possess
    measurement_t    mr_enclave;     // ( 64) The value of the enclave's
                                     //       ENCLAVE measurement
    uint8_t          reserved2[32];  // ( 96)
    measurement_t    mr_signer;      // (128) The value of the enclave's
                                     //       SIGNER measurement
    uint8_t          reserved3[32];  // (160)
    measurement_t    mr_reserved1;   // (192)
    measurement_t    mr_reserved2;   // (224)
    prod_id_t        isv_prod_id;    // (256) Product ID of the Enclave
    isv_svn_t        isv_svn;        // (258) Security Version of the
                                     //       Enclave
    uint8_t          reserved4[60];  // (260)
    report_data_t    report_data;    // (320) Data provided by the user
} report_body_t;

#pragma pack(push, 1)

typedef uint8_t epid_group_id_t[4];

typedef struct basename_t
{
    uint8_t                 name[32];
} basename_t;

typedef struct quote_nonce_t
{
    uint8_t                 rand[16];
} quote_nonce_t;

#define QUOTE_UNLINKABLE_SIGNATURE 0
#define QUOTE_LINKABLE_SIGNATURE   1

typedef struct quote_t {
    uint16_t         version;        // 0
    uint16_t         sign_type;      // 2
    epid_group_id_t  epid_group_id;  // 4
    isv_svn_t        qe_svn;         // 8
    uint8_t          reserved[6];    // 10
    basename_t       basename;       // 16
    report_body_t    report_body;    // 48
    uint32_t         signature_len;  // 432
    uint8_t          signature[];    // 436
} quote_t;

#pragma pack(pop)

#endif

