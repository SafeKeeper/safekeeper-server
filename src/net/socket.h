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

#ifndef _SOCKET_H
#define _SOCKET_H

#include <netinet/in.h>
#include <stdbool.h>
#include <sys/time.h>

typedef int (*incoming_connection_handler)(int);

int init_socket(const char* hostname, in_port_t port, bool server_side, const char* localaddr);
int init_tcp_server(int sd);
int accept_tcp_connections(int sd, incoming_connection_handler new_conn);
int write_all(int fd, const void* buf, size_t count);
int read_all(int sd, void* buf, size_t count);

#endif
