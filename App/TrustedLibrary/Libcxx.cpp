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

#include <stdio.h>

#include "../App.h"
#include "Enclave_u.h"

/* ecall_libcxx_functions:
 *   Invokes standard C++ functions.
 */

void ecall_libcxx_bloom_init(int entries, double error)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_bloom_init(global_eid, entries, error);
	if (ret != SGX_SUCCESS)
		abort();
}
void ecall_libcxx_bloom_add(char *buffer, size_t len)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_bloom_add(global_eid, buffer, len, 1);
	if (ret != SGX_SUCCESS)
		abort();
}

void ecall_libcxx_map_init()
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_map_init(global_eid);
	if (ret != SGX_SUCCESS)
		abort();
}

void ecall_libcxx_random_get(int num)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_random_get(global_eid, num);
	printf("status from random_get: %d\n", ret);
	if (ret != SGX_SUCCESS)
		abort();
}
void ecall_libcxx_bloom_test(void)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_bloom_init(global_eid, 100000, 0.01);
	if (ret != SGX_SUCCESS)
		abort();
}
void ecall_libcxx_encrypt(char *decMessageIn, size_t len, char *encMessageOut, size_t lenOut, int userId)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	
	ret = ecall_encrypt(global_eid, decMessageIn, len, encMessageOut, lenOut, userId);	
	if (ret != SGX_SUCCESS)
		abort();
}

void ecall_libcxx_decrypt(char *encMessageIn, size_t len, char *decMessageOut, size_t lenOut, int userId)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	
	ret = ecall_decrypt(global_eid, encMessageIn, len, decMessageOut, lenOut, userId);
	if (ret != SGX_SUCCESS)
		abort();

}

void ecall_libcxx_encrypt_with_key(char *decMessageIn, size_t len, char *encMessageOut, size_t lenOut, uint8_t *key, size_t newKeySize)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	
	ret = ecall_encrypt_with_key(global_eid, decMessageIn, len, encMessageOut, lenOut, key, newKeySize);	
	if (ret != SGX_SUCCESS)
		abort();
}

void ecall_libcxx_decrypt_with_key(char *decMessageIn, size_t len, char *encMessageOut, size_t lenOut, uint8_t *key, size_t newKeySize)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	
	ret = ecall_decrypt_with_key(global_eid, decMessageIn, len, encMessageOut, lenOut, key, newKeySize);	
	if (ret != SGX_SUCCESS)
		abort();
}
void ecall_libcxx_reEncryption(size_t plaintMsgLen, char* encMessageIn, size_t len, char *resultOut, size_t rstOut, int userId)
{
	
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	
	ret = ecall_reEncryption(global_eid, plaintMsgLen, encMessageIn, len, resultOut, rstOut, userId);	
	if (ret != SGX_SUCCESS)
		abort();
}

void ecall_libcxx_makeComment(char* encComment, size_t encCommentLen, size_t plainCommentLen, size_t pid_msg, int userId)
{
	
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	
	ret = ecall_makeComment(global_eid, encComment, encCommentLen, plainCommentLen, pid_msg, userId);	
	if (ret != SGX_SUCCESS)
		abort();
}
void ecall_libcxx_md5(char *msg, size_t msgLen, char *msgOut, size_t *msgOutLen)
{
	
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	
	ret = ecall_md5(global_eid, msg, msgLen, msgOut, msgOutLen);	
	if (ret != SGX_SUCCESS)
		abort();
}

void ecall_libcxx_sys_reg(int *id, uint8_t *key, size_t k_len)
{
	
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	
	ret = ecall_sys_reg(global_eid, id, key, k_len);	
	if (ret != SGX_SUCCESS)
		abort();
}
void ecall_libcxx_message_posting(char *encMessage, size_t encMsgLen, size_t decMsgLen, char *rstOut, size_t rst_len, int uid)
{
	
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	
	ret = ecall_message_posting(global_eid, encMessage, encMsgLen, decMsgLen, rstOut, rst_len, uid);	
	if (ret != SGX_SUCCESS)
		abort();
}

void ecall_libcxx_feedback(char *enc_feedback, size_t enc_feedback_len, size_t feedback_len, size_t msg_len, int uid)
{
	
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	
	ret = ecall_feedback(global_eid, enc_feedback, enc_feedback_len, feedback_len, msg_len, uid);	
	if (ret != SGX_SUCCESS)
		abort();
}
