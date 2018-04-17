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

#include <phpcpp.h>
#include <iostream>

#define BUFFERSIZE 8192
#include <b64/encode.h>

#include "safekeeper.h"
#include "socket.h"

#define QUOTE_SIZE 1116
#define HEX_CMAC_SIZE 32

static sgx_enclave_id_t eid = 0;
static nrt_ra_context_t ra_context;
static std::string b64quote;

Php::Value sgx_cmac(Php::Parameters &params)
{
    std::string result;
    char cmac[HEX_CMAC_SIZE];
    int sd;
    std::string pass = params[0];
    const char *password = pass.c_str();

    sd = init_socket("localhost", 7000, false, NULL);
    if( sd == -1 ) {
        return "Error: cannot connect to SGX server";
    }

    if( write_all(sd, password, strlen(password) + 1) == -1 ) {
        return "Error: cannot send data to SGX server";
    }
    if( read_all(sd, cmac, HEX_CMAC_SIZE) != HEX_CMAC_SIZE ) {
        return "Error: cannot read data from SGX server";
    }

    result.assign(cmac);
    return result;
}

Php::Value test(Php::Parameters &parameters)
{
    std::cout << "test called" << std::endl;
}

/* Get the quote */
Php::Value sgx_get_quote()
{
    int sd;

    uint8_t quote[QUOTE_SIZE];
    // Base64 encoding: 3 bytes of input -> 4 bytes of output
    // Output is padded to multiple of 4
    // One more for '\0' terminating
    char encoded_quote[(QUOTE_SIZE*2) + 4] = {0};
    std::string result;

    if( b64quote.length() != 0 ) {
        return b64quote;
    }

    sd = init_socket("localhost", 7000, false, NULL);
    if( sd == -1 ) {
        return "Error: cannot connect to SGX server";
    }
    // 6 = length of "quote" + terminating null
    if( write_all(sd, "quote", 6) == -1 ) {
        return "Error: cannot send data to SGX server";
    }
    if( read_all(sd, quote, QUOTE_SIZE) != QUOTE_SIZE ) {
        return "Error: cannot read data from SGX server";
    }

    print_quote((quote_t*)quote);
    base64::encoder b64enc( (QUOTE_SIZE*4)/3 + 4 );
    memset( &b64enc, 0, sizeof(b64enc) );
    b64enc.encode( (const char*)quote, QUOTE_SIZE, encoded_quote );

    result.assign(encoded_quote);
    b64quote = result;

    return result;
}

extern "C" {

   /* *
     *  Function that is called by PHP right after the PHP process
     *  has started, and that returns an address of an internal PHP
     *  strucure with all the details and features of your extension
     *
     *  @return void*   a pointer to an address that is understood by PHP*/

    PHPCPP_EXPORT void *get_module()
    {
        // static(!) Php::Extension object that should stay in memory
        // for the entire duration of the process (that's why it's static)
        static Php::Extension sgx_extension("sgx_extension", "1.0");

        // This won't work in the current model
        // Need to explicitly call sgx_init() from PHP
        // Because the ini is not registered so sgx_init() call from here
        // won't have access to this variable
        sgx_extension.add(Php::Ini("safekeeper.enclave", "safekeeper.signed.so"));

        sgx_extension.add<test>("sgx_test");
        sgx_extension.add<sgx_cmac>("sgx_cmac");
        sgx_extension.add<sgx_get_quote>("sgx_get_quote");

        // return the extension
        return sgx_extension;
    }
}
