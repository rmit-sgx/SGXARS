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


#include <cstdlib>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include "../Enclave.h"
#include "Enclave_t.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include <map>
#include <unordered_map>
#define BUFLEN 2048
#define KEY_SIZE 16
#define NUM_USER 1
#define test_map 1
// #define test_unordered_map 1
//#define test_array_init 1
//#define test_array 1
#define NUM_USER_SCORE 100000
struct bloom *bloom = (struct bloom*)malloc(sizeof(struct bloom));
int bloom_check(char*,size_t,int);
void printList();
int hashmap_hash_int(char*, size_t);
bool swapUserId(int, int);
void itos(char*, int, int);
void md5();
// User reputationList[NUM_USER];
// stored within sgx only
static sgx_aes_gcm_128bit_key_t key = { 0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0xf7, 0x72 };
// this is used to store user ids and their keys
typedef struct aeskey
{
	sgx_aes_gcm_128bit_key_t key;
	int id;
    bool operator<(const aeskey& t1) const { return (id < t1.id); } 
	bool operator==(const aeskey& t1) const { return (id == t1.id ); }
} aesKey;
#ifdef test_unordered_map
//namespace std
//{
//    template<> struct hash<aeskey>
//    {
//        std::size_t operator()(aeskey const& s) const noexcept
//        {
//            std::size_t h2 = std::hash<uint8_t*>{}((uint8_t*)s.key);
//            std::size_t h1 = std::hash<int>{}(s.id);
//            return h1 ^ (h2 << 1); // or use boost::hash_combine
//        }
//    };
//}

std::map<int, aesKey> userList; 
// this is used to store reputation
std::map<int, int> repuList;
#endif
#ifdef test_map
std::map<int, aesKey> userList;
std::map<aesKey, int> repuList;
#endif

typedef struct node
{
	int id;
	int score;
	uint8_t key[16];
} Node;
Node *user_list = NULL;
void ecall_bloom_init(int entries, double error)
{
	  bloom->ready = 0;

  if (entries < 1000 || error == 0.0) {
	printf("failed to initialise due to %d enteries not met, should be greater than 1000.\n", entries);
  }

  bloom->entries = entries;
  bloom->error = error;

  double num = log(bloom->error);
  double denom = 0.480453013918201; // ln(2)^2
  bloom->bpe = -(num / denom);

  double dentries = (double)entries;
  bloom->bits = (int)(dentries * bloom->bpe);

  if (bloom->bits % 8) {
    bloom->bytes = (bloom->bits / 8) + 1;
  } else {
    bloom->bytes = bloom->bits / 8;
  }

  bloom->hashes = (int)ceil(0.693147180559945 * bloom->bpe);  // ln(2)

  bloom->bf = (unsigned char *)calloc(bloom->bytes, sizeof(unsigned char));
  if (bloom->bf == NULL) {                                   // LCOV_EXCL_START
	printf("failed to calloc %d bytes.\n", bloom->bytes);
  }                                                          // LCOV_EXCL_STOP

  bloom->ready = 1;
}
	
int test_bit_set_bit(unsigned char * buf,
                                   unsigned int x, int set_bit)
{
  unsigned int byte = x >> 3;
  unsigned char c = buf[byte];        // expensive memory access
  unsigned int mask = 1 << (x % 8);

  if (c & mask) {
    return 1;
  } else {
    if (set_bit) {
      buf[byte] = c | mask;
    }
    return 0;
  }
}

unsigned int murmurhash2(const void * key, int len, const unsigned int seed)
{
	// 'm' and 'r' are mixing constants generated offline.
	// They're not really 'magic', they just happen to work well.

	const unsigned int m = 0x5bd1e995;
	const int r = 24;

	// Initialize the hash to a 'random' value

	unsigned int h = seed ^ len;

	// Mix 4 bytes at a time into the hash

	const unsigned char * data = (const unsigned char *)key;

	while(len >= 4)
	{
		unsigned int k = *(unsigned int *)data;

		k *= m;
		k ^= k >> r;
		k *= m;

		h *= m;
		h ^= k;

		data += 4;
		len -= 4;
	}

	// Handle the last few bytes of the input array

	switch(len)
	{
	case 3: h ^= data[2] << 16;
	case 2: h ^= data[1] << 8;
	case 1: h ^= data[0];
	        h *= m;
	};

	// Do a few final mixes of the hash to ensure the last few
	// bytes are well-incorporated.

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}
void ecall_encrypt_with_key(char *decMessageIn, size_t len, char *encMessageOut, size_t lenOut, uint8_t *new_key, size_t newKeySize)
{
	uint8_t *origMessage = (uint8_t *) decMessageIn;
	uint8_t p_dst[BUFLEN] = {0};
	sgx_aes_gcm_128bit_key_t k = {0};
	
	for (int i = 0; i < newKeySize; i++)
		k[i] = new_key[i];

	// Generate the IV (nonce)
	sgx_read_rand(p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);

	sgx_rijndael128GCM_encrypt(
		&k,
		origMessage, len, 
		p_dst + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) (p_dst));	
	memcpy(encMessageOut,p_dst,lenOut);
}



void ecall_encrypt(char *decMessageIn, size_t len, char *encMessageOut, size_t lenOut, int userId)

{
	uint8_t *origMessage = (uint8_t *) decMessageIn;
	uint8_t p_dst[BUFLEN] = {0};

	// Generate the IV (nonce)
	sgx_read_rand(p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);
	aesKey key = userList.find(userId)->second;
	printf("ecall_enc:: id:%d, key:%s\n", userId, key.key);
	sgx_rijndael128GCM_encrypt(
		&key.key,
		origMessage, len, 
		p_dst + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) (p_dst));	
	memcpy(encMessageOut,p_dst,lenOut);
}

void itoc(char *src, int n)
{
	char bytes[4] = { 0 };
	bytes[0] = (n >> 24) & 0xFF;
	bytes[1] = (n >> 16) & 0xFF;
	bytes[2] = (n >> 8) & 0xFF;
	bytes[3] = n & 0xFF;
	memcpy(src, bytes, 4);
}

void ctoi(char *src, int *n)
{
	int tmp = 0;
	for (int i =0; i < 4; i++)
		printf("%x ", src[i]);
	tmp |= ((int)src[0]) & 0xFF;
	tmp |= ((int)src[1] << 8) & 0xFFFF;
	tmp |= ((int)src[2] << 16) & 0xFFFFFF;
	tmp |= ((int)src[3] << 24) & 0xFFFFFFFF;
	printf("result from ctoi: %d\n", tmp);
	*n = tmp;
}

void ecall_message_posting(char *encMessage, size_t encMsgLen, size_t decMsgLen, char *rstOut, size_t rst_len, int uid)
{
	// decrypt message
	char *decMessage = (char*)malloc(decMsgLen);
	ecall_decrypt(encMessage, encMsgLen, decMessage, decMsgLen, uid);
	size_t msg_len = decMsgLen - 4;
	char *uid_c = (char*)malloc(4);
	char *msg = (char*)malloc(msg_len);
	memcpy(msg, decMessage, msg_len);
	memcpy(uid_c, decMessage+msg_len, 4);
	int new_uid = 0;
	ctoi(uid_c, &new_uid);
	swapUserId(uid, new_uid);	
	decMessage = (char*)malloc(decMsgLen);
	
	// compute pid
	char *md5_msg = (char*)malloc(16);
	size_t md5_msg_len;
	ecall_md5(msg, msg_len, md5_msg, &md5_msg_len);
	
	size_t pid_len = 32;
	char *pid = (char*)malloc(pid_len);
	memcpy(pid, md5_msg, md5_msg_len);
	memcpy(pid+md5_msg_len, userList.find(new_uid)->second.key, KEY_SIZE);
	printf("plain pid:%s\n", pid);
	size_t encPidLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + pid_len);
	char *encPid = (char*)malloc(encPidLen);
	ecall_encrypt(pid, pid_len, encPid, encPidLen, new_uid);
	memcpy(rstOut, encPid, encPidLen);	
	memcpy(rstOut+encPidLen, msg, msg_len);
}

void ecall_feedback(char *enc_feedback, size_t enc_feedback_len, size_t feedback_len, size_t msg_len, int uid)
{
	char *dec_feedback = (char*)malloc(feedback_len);
	ecall_decrypt(enc_feedback, enc_feedback_len, dec_feedback, feedback_len, uid);
	printf("ecall_feedback:: %s\n", dec_feedback);
	int response = 0;
	if (dec_feedback[0] == '1')
		response = 1;
	
	char *msg = (char*)malloc(msg_len);
	size_t pid_len = feedback_len - msg_len - 5;
	char *pid = (char*)malloc(pid_len);
	int new_id = 0;
	memcpy(msg, dec_feedback+1, msg_len);
	memcpy(pid, dec_feedback+1+msg_len, pid_len);
	memcpy(&new_id, dec_feedback+1+msg_len+pid_len, 4);
	printf("ecall_feedback::id: %d, msg: %s, pid: %s\n", new_id, msg, pid);
	// decrypt pid with uid
	size_t plain_pid_len = 32;
	char *plain_pid = (char*)malloc(plain_pid_len);
	ecall_decrypt(pid, pid_len, plain_pid, plain_pid_len, uid);
	printf("ecall_feedback::plain pid: %s\n", plain_pid);
	swapUserId(uid, new_id);
	
	int score = repuList.find(userList.find(new_id)->second)->second;
	printf("score is %d\n", score);
	char *feedback_validity_check = (char*)malloc(plain_pid_len+sizeof(int));
	memcpy(feedback_validity_check, &new_id, 4);
	memcpy(feedback_validity_check+4, plain_pid, plain_pid_len);
	
	ecall_bloom_check(feedback_validity_check, 36, 1);
	
	if (bloom_check(feedback_validity_check, 36, 1))
		repuList.find(userList.find(new_id)->second)->second += response;
	printf("after updating, score is %d\n", repuList.find(userList.find(new_id)->second)->second);
}

void ecall_reEncryption(size_t plaintMsgLen, char *encMessageIn, size_t len, char *resultOut, size_t rstOut, int userId)
{
	char *plainMsg = (char*)malloc(plaintMsgLen+1*sizeof(char));
	//ecall_decrypt(encMessageIn, len, plainMsg, plaintMsgLen, userId);
	plainMsg[plaintMsgLen] = '\0';
	int msgLen = plaintMsgLen - 5;
	char *msg = (char*)malloc(msgLen);
	memcpy(msg, plainMsg, msgLen);
	char *newId = (char*)malloc(5);
	memcpy(newId, plainMsg+(msgLen), 5);
	int intId = atoi(newId);
	swapUserId(userId, intId);
	// combine both plain message to generate pid (message,k_user)	

	char *md5_msg = (char*)malloc(16);
	size_t md5_msg_len;
	ecall_md5(msg, msgLen, md5_msg, &md5_msg_len);	
	
	char *pid = (char*)malloc(32);
	char *backup = pid;
	memcpy(pid, md5_msg, md5_msg_len);
	//pid += 16;
	memcpy(pid+16, userList.find(intId)->second.key, KEY_SIZE);
	//pid = backup;
	//backup = NULL;
	
	size_t pidLen = KEY_SIZE + md5_msg_len;
	size_t encPidLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + pidLen);
	//printf("ecall_encrypt: encPidLen: %d\n", encPidLen);
	char *encryptedPid = (char*)malloc(encPidLen+1*sizeof(char));
	ecall_encrypt(pid, pidLen, encryptedPid, encPidLen, intId);
	ocall_test(encryptedPid, encPidLen, msg, msgLen);



	// encryptedPid[encPidLen] = '\0';
	// printf("encrypted pid: %s\n", encryptedPid);
	//printf("ecall_encrypt: sizeof encPidLen: %d\n", encPidLen);
	//printf("ecall_encrypt: sizeof pidLen: %d\n", pidLen);
//	char *testingdecryption = (char*)malloc(pidLen);
//	ecall_decrypt(encryptedPid, encPidLen, testingdecryption, pidLen);
//	testingdecryption[pidLen] = '\0';
//	printf("testingdecryption: %s\n", testingdecryption);
}
bool swapUserId(int prevId, int userId)
{
	#ifdef test_map
	auto result = userList.find(prevId);
	if ( result != userList.end() )
	{
		if (result->first == prevId)
			printf("id: %d existed.\n", result->first);
		else
			printf("id: %d is good. New id: %d\n", result->first, userId);
		std::swap(userList[userId], result->second);
		userList.erase(result);
	}
	#endif
	
	#ifdef test_unordered_map
	auto result_1 = userList.find(prevId);
	if ( result_1 != userList.end() )
	{
		if (result_1->first == prevId)
			printf("id: %d existed.\n", result_1->first);
		else
			printf("id: %d is good. New id: %d\n", result_1->first, userId);
		std::swap(userList[userId], result_1->second);
		userList.erase(result_1);
	}
	#endif
	#ifdef test_array_
	for (int i = 0; i < NUM_USER_SCORE; i++)
		if (user_list[i].id == prevId)
		{
			user_list[i].id = userId;
			break;
		}
	#endif
}
void ecall_makeComment( char *encComment, size_t encCommentLen, size_t plainCommentLen, size_t msgLen, int userId)
{
	char *decComment = (char*)malloc(plainCommentLen);	
	char *encComment_backup = (char*)malloc(encCommentLen);
	memcpy(encComment_backup, encComment, encCommentLen);
	ecall_decrypt(encComment_backup, encCommentLen, decComment, plainCommentLen, userId);
	decComment[encCommentLen] = '\0';
	char *backup = decComment;
	uint8_t reaction = (uint8_t)(decComment[0] - '0');
	char *message = (char*)malloc(msgLen);
	char *pid = (char*)malloc(plainCommentLen-msgLen-1);
	char *newCommenterId = (char*)malloc(5);
	backup++;
	memcpy(message, backup, msgLen);
	backup += msgLen;
	memcpy(pid, backup, plainCommentLen-msgLen-6);
	backup += plainCommentLen-msgLen-6;
	memcpy(newCommenterId, backup, 5);
	int newCommenterIdInt = atoi(newCommenterId);
	swapUserId(userId, newCommenterIdInt);
	
	#ifdef test_map
	int repuScore = repuList.find(userList.find(newCommenterIdInt)->second)->second;
	#endif
	#ifdef test_unordered_map
	int repuScore = repuList.find(userList.find(newCommenterIdInt)->second.id)->second;
	#endif
	char* idPid = (char*)malloc(37);
	// sprintf(idPid, "%d", userId);
	itos(idPid, userId, 5);
	
	char *plainPid = (char*) malloc(33);
	size_t plainPidLen = 32;
	ecall_decrypt(pid, 32, plainPid, plainPidLen, 12346);
	plainPid[plainPidLen] = '\0';

	// retrieve pid(hash(m), key)
	aesKey key;
	memcpy(key.key, plainPid+16, 16);
	key.id = 0;
	// as we are using stl map with custom objects as the key value,
	// an integer is required due to the way that stl map is implemented
	memcpy(idPid+5, plainPid, plainPidLen);
	ecall_bloom_check(idPid, 37, 1);
	ocall_finalise(plainPid, plainPidLen+1);
	#ifdef test_map
	aesKey user = userList.find(userId)->second;
	if (bloom_check(idPid, 37, 1))
		repuList.find(key)->second += reaction;
	#endif
	#ifdef test_unordered_map
	if (bloom_check(idPid, 37, 1))
		repuList.find(key.id)->second += reaction;
	#endif
	#ifdef test_array_
	if (bloom_check(idPid, 37, 1))
		for (int i = 0; i < NUM_USER_SCORE; i++)
			if (strcmp((const char*)key.key, (const char*)user_list[i].key) == 0)
				user_list[i].score += reaction;
	#endif
	
	// printf("repuList: %d\n", repuList.find(user)->second);
	// printf("plain: %s\n", plainPid);
}

void printList()
{
	printf("\n%d printing:\n", 12345);
	for (int i = 0; i < 16; i++)
		printf("%02x", userList.find(12345)->second.key[i]);
	printf("\n%d printing:\n", 12346);
	for (int i = 0; i < 16; i++)
		printf("%02x", userList.find(12346)->second.key[i]);
	printf("\n%d printing:\n", 99998);
	for (int i = 0; i < 16; i++)
		printf("%02x", userList.find(99998)->second.key[i]);
	printf("\n%d printing:\n", 99999);
	for (int i = 0; i < 16; i++)
		printf("%02x", userList.find(99999)->second.key[i]);
}

void itos(char *dest, int src, int digit)
{
		dest[0] = (src / 10000) + '0';
		dest[1] = (src / 1000%10) + '0';
		dest[2] = (src / 100%10) + '0';
		dest[3] = (src / 10%10) + '0';
		dest[4] = (src % 10) + '0';
}

void ecall_decrypt(char *encMessageIn, size_t len, char *decMessageOut, size_t lenOut, int userId)
{
	uint8_t *encMessage = (uint8_t *) encMessageIn;
	uint8_t p_dst[BUFLEN] = {0};
	aesKey key = userList.find(userId)->second;
	sgx_rijndael128GCM_decrypt(
		&key.key,
		encMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		lenOut,
		p_dst,
		encMessage + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) encMessage);
	memcpy(decMessageOut, p_dst, lenOut);
}

int hashmap_hash_int(char* s, size_t len)
{

  unsigned int i;
  unsigned long crc32val;
  
  crc32val = 0;
  for (i = 0;  i < len;  i ++)
    {
      crc32val =
	crc32_tab[(crc32val ^ s[i]) & 0xff] ^
	  (crc32val >> 8);
    }
	unsigned long key = crc32val;
	/* Robert Jenkins' 32 bit Mix Function */
	key += (key << 12);
	key ^= (key >> 22);
	key += (key << 4);
	key ^= (key >> 9);
	key += (key << 10);
	key ^= (key >> 2);
	key += (key << 7);
	key ^= (key >> 12);

	/* Knuth's Multiplicative Method */
	key = (key >> 3) * 2654435761;

	return key % NUM_USER;
}
void ecall_decrypt_with_key(char *encMessageIn, size_t len, char *decMessageOut, size_t lenOut, uint8_t *new_key, size_t newKeySize)
{
	uint8_t *encMessage = (uint8_t *) encMessageIn;
	uint8_t p_dst[BUFLEN] = {0};

	sgx_aes_gcm_128bit_key_t k = {0};
	
	for (int i = 0; i < newKeySize; i++)
		k[i] = new_key[i];

	sgx_rijndael128GCM_decrypt(
		&k,
		encMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		lenOut,
		p_dst,
		encMessage + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) encMessage);
	memcpy(decMessageOut, p_dst, lenOut);
}
int bloom_check(char *buffer, size_t len, int add)
{
	  if (bloom->ready == 0) {
    printf("bloom at %p not initialized!\n", (void *)bloom);
  }

	//ocall_test(buffer, len);
  int hits = 0;
  register unsigned int a = murmurhash2(buffer, len, 0x9747b28c);
  register unsigned int b = murmurhash2(buffer, len, a);
  register unsigned int x;
  register unsigned int i;

  for (i = 0; i < bloom->hashes; i++) {
    x = (a + i*b) % bloom->bits;
    if (test_bit_set_bit(bloom->bf, x, add)) {
      hits++;
    } else if (!add) {
      // Don't care about the presence of all the bits. Just our own.
      return 0;
    }
  }

  if (hits == bloom->hashes) {
    return 1;                // 1 == element already in (or collision)
  }
  else {
	return 0;
  }
}
void ecall_random_get(int num)
{
	int rand_num = 0;
	sgx_read_rand((uint8_t*)rand_num, 4);
	rand_num %= NUM_USER_SCORE;
	#ifdef test_array_init
	if (user_list == NULL)
	{
		printf("user list is empty.%d\n", 0);
		return;
	}
	for (int i = 0; i < num; i++)
	{
		for (int j = 0; j < NUM_USER_SCORE; j++)
			if (user_list[j].score == rand_num)
				break;
	sgx_read_rand((uint8_t*)rand_num, 4);
	rand_num %= NUM_USER_SCORE;
	}
	#endif
			#ifdef test_map_no
	for (int i = 0; i < num; i++)
		repuList.find(userList.find(rand_num)->second)->second;
			#endif
	#ifdef test_hash
	for (int i = 0 ; i < num; i++)
		md5();	
	#endif
	
}
void ecall_sys_reg(int *id, uint8_t *key, size_t k_len)
{
	int size = userList.size();
	auto result = userList.find(size);	
	if (result == userList.end())
	{
		*id = size+1;
		 aesKey key_pair;
		sgx_aes_gcm_128bit_key_t key_local;
		sgx_read_rand(key, 16);
		memcpy(key_pair.key, key_local, 16);
		key_pair.id = size+1;
		userList.insert(std::pair<int, aesKey>(key_pair.id, key_pair));
		memcpy(key, key_local, k_len);
		repuList.insert(std::pair<aesKey, int>(key_pair, 0));
	}
}

void ecall_map_init()
{
	#ifdef test_array_init
	user_list = (Node*)malloc(sizeof(Node) * NUM_USER_SCORE);
	
	if (user_list!=NULL)
	{
	for (int i = 0; i < NUM_USER_SCORE; i++)
	{
		(user_list+i)->id = i;
		memcpy((user_list+i)->key, key, 16);
		(user_list+i)->score = i+2;
	}
	}
	else printf("failed to allocate %d bytes.\n", sizeof(Node) * NUM_USER_SCORE);
	#endif
	
	for (int i = 0; i < NUM_USER_SCORE; i++)
	{
		aesKey newKey;
		memcpy(newKey.key, key, 16);
		newKey.id = i;
		userList.insert(std::pair<int, aesKey>(newKey.id, newKey));
		#ifdef test_unordered_map
		repuList.insert(std::pair<int, int>(newKey.id, 123));
		#endif
		#ifdef test_map
		repuList.insert(std::pair<aesKey, int>(newKey, 123));
		#endif
	}
	aesKey newKey2 = {{  0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0xf7, 0x99 }, 1074629};
	userList.insert(std::pair<int, aesKey>(99998, newKey2));	
	#ifdef test_map
	repuList.insert(std::pair<aesKey, int>(newKey2, 345345));
	#endif
	#ifdef test_unordered_map
	repuList.insert(std::pair<int, int>(newKey2.id, 345345));
	#endif
	// if (repuResult != repuList.end())
	printf("size of userList: %d, repuList: %d\n\n", userList.size(), repuList.size());
}

void ecall_bloom_add(char *buffer, size_t len, int add)
{
	  if (bloom->ready == 0) {
    printf("bloom at %p not initialized!\n", (void *)bloom);
  }

	//ocall_test(buffer, len);
  int hits = 0;
  register unsigned int a = murmurhash2(buffer, len, 0x9747b28c);
  register unsigned int b = murmurhash2(buffer, len, a);
  register unsigned int x;
  register unsigned int i;

  for (i = 0; i < bloom->hashes; i++) {
    x = (a + i*b) % bloom->bits;
    if (test_bit_set_bit(bloom->bf, x, add)) {
      hits++;
    } else if (!add) {
      // Don't care about the presence of all the bits. Just our own.
		printf("%s is not here.\n", buffer);
		break;
      // return 0;
    }
  }

  if (hits == bloom->hashes) {
    // return 1;                // 1 == element already in (or collision)
	printf("%s may be there, length: %d\n",buffer, len);
  }
  else {
    printf("%s is not here.\n", buffer);
  }

  // return 0;
}
void md5()
{
	EVP_MD_CTX *mdctx;
 	const EVP_MD *md;
	unsigned int md_len;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	md = EVP_md5();
	mdctx = EVP_MD_CTX_new();
 	EVP_DigestInit_ex(mdctx, md, NULL);
 	EVP_DigestUpdate(mdctx, key, 16);
 	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
 	EVP_MD_CTX_free(mdctx);
}

void ecall_md5(char* msg, size_t msgLen, char *msgOut, size_t *msgOutLen)
{
	EVP_MD_CTX *mdctx;
 	const EVP_MD *md;
	unsigned int md_len;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	md = EVP_md5();
	mdctx = EVP_MD_CTX_new();
 	EVP_DigestInit_ex(mdctx, md, NULL);
 	EVP_DigestUpdate(mdctx, msg, msgLen);
 	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
 	EVP_MD_CTX_free(mdctx);
	memcpy(msgOut, md_value, md_len);
	*msgOutLen = md_len;
}
void ecall_bloom_check(char *buffer, size_t len, int add)
{
	ecall_bloom_add(buffer, len, add);
	
}
