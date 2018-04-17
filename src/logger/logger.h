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

#ifndef _LOGGER_H
#define _LOGGER_H

#include <stdio.h>

#define MODULE_NAME_LEN 30

struct logger
{
  FILE* f_print;
  FILE* f_debug;
  FILE* f_error;
  char module[MODULE_NAME_LEN];
};

struct logger* init_logger(FILE *print_file, FILE *debug_file, FILE *error_file,
                           const char* module);
void log_print(const struct logger* l, const char* format, ...);
void log_debug(const struct logger* l, const char* format, ...);
void log_error(const struct logger* l, const char* format, ...);
void shutdown_logger(struct logger* l);

#endif

