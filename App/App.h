/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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
 *
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
 *
 */


#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "../Globals.hpp"
#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"

extern sgx_enclave_id_t global_eid;    /* global enclave id */

#if defined(__cplusplus)
extern "C" {
#endif

// void edger8r_array_attributes(void);
// void edger8r_type_attributes(void);
// void edger8r_pointer_attributes(void);
// void edger8r_function_attributes(void);

//void ecall_libc_functions(void);
//void ecall_libcxx_functions(void);
//void ecall_thread_functions(void);
void ecall_libcxx_bloom_test(void);
void ecall_libcxx_bloom_init(int, double);
void ecall_libcxx_bloom_add(char*, size_t);
void ecall_libcxx_bloom_check(char*, size_t);
void ecall_libcxx_encrypt(char*, size_t, char*, size_t, int);
void ecall_libcxx_decrypt(char*, size_t, char*, size_t, int);
void ecall_libcxx_encrypt_with_key(char*, size_t, char*, size_t, uint8_t*, size_t);
void ecall_libcxx_decrypt_with_key(char*, size_t, char*, size_t, uint8_t*, size_t);
void ecall_libcxx_reEncryption(size_t, char*, size_t, char*, size_t, int);
void ecall_libcxx_makeComment(char*, size_t, size_t, size_t, int);
void ecall_libcxx_md5(char *, size_t, char *, size_t *);
void ecall_libcxx_map_init();
void ecall_libcxx_random_get(int num);
void ecall_libcxx_sys_reg(int *, uint8_t *, size_t);
void ecall_libcxx_message_posting(char *encMessage, size_t encMsgLen, size_t decMsgLen, char *rstOut, size_t rst_len, int uid);
void ecall_libcxx_feedback(char *, size_t, size_t, size_t, int);
#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */