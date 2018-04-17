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

#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <poll.h>

#include <curl/curl.h>
#include <nrt_ukey_exchange.h>

#include <sgx_urts.h>
#include <sgx_uae_service.h>

#include "enclave_u.h"

#include "logger.h"
#include "socket.h"

#include "sgx_errors.h"

#include "safekeeper.h"

#define ENCLAVE_PATH "build/enclave/enclave.signed.so"
#define HOSTNAME_SIZE 255
#define BUF_SIZE 2048
#define QUOTE_SIZE 1116
#define CMAC_SIZE 16

static struct logger* l = NULL;
static sgx_enclave_id_t eid = 0;
static nrt_ra_context_t ra_context;

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


void usage()
{
    printf("\n Usage: safekeeper -i <ip address> -p <port>\n\n");
}

int sgx_init(nrt_ra_context_t *p_ra_context) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = create_enclave(ENCLAVE_PATH, &eid);

    if (ret != SGX_SUCCESS)
        return -1;

    ret = enclave_init(eid, NULL, 0);
    if (ret != SGX_SUCCESS)
        return -1;

    ret = enclave_init_ra(eid, p_ra_context);
    if (ret != SGX_SUCCESS)
        return -1;

    return 0;
}

/* Get the quote */
sgx_status_t sgx_get_quote(uint8_t* quote)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = obtain_quote(eid, ra_context, quote);
    if (ret != SGX_SUCCESS)
        return ret;
    return SGX_SUCCESS;
}

// Utilities
int bytes2hex(const uint8_t* bytes, int len, char* res) {
    for(int i = 0; i < len; i++) {
        sprintf(&(res[i*2]), "%02hhx", bytes[i]);
    }

    return 0;
}

/* Produce cmac of password */
sgx_status_t sgx_cmac(const char* pass, char* hex_cmac)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_cmac_128bit_tag_t tag_cmac;

    ret = enclave_process(eid, ra_context, pass, &tag_cmac);
    if (ret != SGX_SUCCESS)
        return ret;

    bytes2hex( (const uint8_t*)&tag_cmac, CMAC_SIZE, hex_cmac );

    return SGX_SUCCESS;
}

int parse_parameters(int argc, char *argv[],
        char* hostname, in_port_t* port)
{
    int c = 0;

    while((c = getopt(argc,argv,"hi:p:")) != -1){
        switch(c){
        case 'i':
            if( strlen(optarg) < HOSTNAME_SIZE )
                strcpy(hostname, optarg);
            else {
                log_error(l, "Error: given hostname/ip_address is too long.\n");
                return -1;
            }
            break;
        case 'p':
            if( (*port=atoi(optarg)) == 0 ) {
                log_error(l, "Error: invalid port number. Give a number between 1 and 65535.\n");
                return -1;
            }
            break;

        case 'h':
        default:
            usage();
            return -1;
            break;
        }
    }

    return 0;
}

int server_socket(const char* hostname, in_port_t port)
{
    int sd;

    if( (sd = init_socket(hostname, port, true, NULL)) == -1 ){
        log_error(l, "Socket init failed.\n");
        return -1;
    }

    return sd;
}

int handle_client(int sd)
{
    char buf[BUF_SIZE] = {0};
    int n;
    uint8_t quote[QUOTE_SIZE];
    // Hex + last zero-byte
    char cmac[CMAC_SIZE*2 + 1];
    sgx_status_t ret;

    log_print(l, "New client connected\n");

    if( (n = read(sd, buf, BUF_SIZE-1)) == -1 ) {
        log_error(l, "Error reading from client\n");
        perror("read");
        close(sd);
        return -1;
    }

    buf[n] = '\0';

    // strlen( "quote" ) = 5
    if( !strncmp( buf, "quote", 5 ) ) {
        if( sgx_get_quote(quote) != SGX_SUCCESS ) {
            log_error(l, "Error getting the SGX quote\n");
            close(sd);
            return -1;
        }
        if( write_all(sd, quote, QUOTE_SIZE) == -1 ) {
            log_error(l, "Error sending the quote to the client\n");
            close(sd);
            return -1;
        };
    } else {
        memset(cmac, 0, sizeof(cmac));
        ret = sgx_cmac( buf, cmac );
        if( ret != SGX_SUCCESS ) {
            log_error(l, "Error processing the password\n");
            print_error_message( ret );
            close(sd);
            return -1;
        }
        if( write_all(sd, cmac, sizeof(cmac)) == -1 ) {
            log_error(l, "Error sending the cmac to the client\n");
            close(sd);
            return -1;
        } else {
            log_print(l, "CMAC is: %s\n", cmac);
        };
    }

    close(sd);
    return 0;
}

int main(int argc, char* argv[])
{
    int ret;
    char hostname[HOSTNAME_SIZE] = "localhost";
    in_port_t port = 7000;
    int server_sd = -1;
    l = init_logger(stdout, stderr, stderr, "Main");

    if( parse_parameters(argc, argv, hostname, &port) )
        exit(EXIT_FAILURE);

    if( sgx_init(&ra_context) == -1 ) {
        log_error(l, "Could not create the enclave.\n");
        exit( EXIT_FAILURE );
    }

    log_print(l, "Will bind to: %s.\n", hostname);
    log_print(l, "Port for clients: %u.\n", port);

    server_sd = server_socket(hostname, port);
    if( server_sd == -1 ) exit(EXIT_FAILURE);

    if( init_tcp_server( server_sd ) == -1 ){
        log_error(l, "Could not initiate the server.\n");
        perror("init_tcp_server");
        exit( EXIT_FAILURE );
    }

    if( (ret = accept_tcp_connections( server_sd, handle_client )) == -1 ){
        log_error(l, "Could not accept a new connection.\n");
        perror("accept_tcp_connections");
    }

    shutdown_logger(l);
    return 0;
}
