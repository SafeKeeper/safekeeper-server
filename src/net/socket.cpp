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

#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "socket.h"
#include "logger.h"

#define DEFAULT_BACKLOG 10
int init_tcp_server(int sd)
{
  if( listen(sd, DEFAULT_BACKLOG) == -1 )
      return -1;
}

int accept_tcp_connections(int sd, incoming_connection_handler new_conn)
{
  int client_sd;
  struct sockaddr client_addr;
  socklen_t client_addr_len = sizeof(client_addr);
  for(;;)
  {
    client_sd = accept(sd, &client_addr, &client_addr_len);
    if( client_sd == -1 )
      return -1;

    (*new_conn)( client_sd );
  }
}

/* Return 0 if two addresses are the same */
int compare_sockaddr(struct sockaddr_storage* a1, struct sockaddr_storage* a2)
{
  if( a1->ss_family != a2->ss_family ) return 1;
  if( a1->ss_family == AF_INET ) {
    if( ((struct sockaddr_in*)a1)->sin_port != ((struct sockaddr_in*)a2)->sin_port ) return 2;
    if( ((struct sockaddr_in*)a1)->sin_addr.s_addr != ((struct sockaddr_in*)a2)->sin_addr.s_addr ) return 3;
    return 0;
  }
  if( a1->ss_family == AF_INET6 ) {
    if( ((struct sockaddr_in6*)a1)->sin6_port != ((struct sockaddr_in6*)a2)->sin6_port ) return 4;
    /* TODO Compare IPv6 addresses */
    return 0;
  }
  return 6;
}

/* Get address information, create socket and bind to the port */
int init_socket(const char* hostname, in_port_t port, bool server_side, const char* localaddr)
{
  char str_port[6] = {0};
  struct addrinfo hints;
  struct sockaddr_in sin;
  struct addrinfo *res, *cur;
  int sd;
  int err = 0;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  sprintf(str_port, "%u", port);
  err = getaddrinfo(hostname, str_port, &hints, &res);
  if( err != 0 ) {
    fprintf(stderr, "Socket init, getaddrinfo(): %s\n", gai_strerror(err));
    return -1;
  }

  for( cur = res; cur != NULL; cur = cur->ai_next )
  {
    if( (sd = socket( cur->ai_family, cur->ai_socktype, cur->ai_protocol )) == -1 )
    {
      perror("Socket init, socket():");
      continue;
    }
    if( server_side && (bind(sd, cur->ai_addr, cur->ai_addrlen) == -1) )
    {
      perror("Socket init, bind():");
      close(sd);
      continue;
    }
    if( !server_side ) {
      if (localaddr != NULL) {
        memset(&sin, 0, sizeof(struct sockaddr_in));
        sin.sin_family = AF_INET;
        sin.sin_port = 0;
        sin.sin_addr.s_addr = inet_addr(localaddr);
        printf("binding");
        if ( bind(sd, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1) {
          perror("Local socket binding, bind():");
          continue;
        }
      }
      if ( connect(sd, cur->ai_addr, cur->ai_addrlen) == -1) {
        perror("Socket init, connect():");
        continue;
      }
    }
    break;
  }

  if( cur == NULL ) sd = -1;

  freeaddrinfo(res);
  return sd;
}

int write_all(int sd, const void* buf, size_t count) {
  const char* p = (char*)buf;
  int n;

  do {
    n = write(sd, p, count);
    if( n == -1 ) {
      return -1;
    }
    count -= n;
    p += n;
  } while( count > 0 );
}

int read_all(int sd, void* buf, size_t count) {
  char* p = (char*)buf;
  int n;

  do {
    n = read(sd, p, count);
    if( n == -1 ) {
      return -1;
    }
    count -= n;
    p += n;
  } while( count > 0 );
}
