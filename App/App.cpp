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
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include <math.h>
#include <unistd.h>
#include <pthread.h>
#include <pwd.h>
#include <openssl/evp.h>
# define MAX_PATH FILENAME_MAX
#include "sgx_trts.h"
#include "sgx_urts.h"
#include "App.h"
#include "utils.hpp"
#include "Enclave_u.h"
#include "ZT.hpp"
#define BUFLEN 2048
#define SGX_AESGCM_MAC_SIZE 16
#define SGX_AESGCM_IV_SIZE 12
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0; static sgx_aes_gcm_128bit_key_t new_key = {0x0, 0x0, 0x1, 0x1,0x0, 0x0, 0x1, 0x1,0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x1, 0x1 };
typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;
char *pid;
char *pid_msg;
size_t pidLen;

///

EC_KEY *ENCLAVE_PUBLIC_KEY = NULL;
unsigned char *enclave_public_key;

uint32_t NUM_EXPECTED_PARAMS = 12;
bool RESUME_EXPERIMENT;
uint32_t DATA_SIZE;
uint32_t MAX_BLOCKS;
int REQUEST_LENGTH;
uint32_t STASH_SIZE;
uint32_t OBLIVIOUS_FLAG = 0;
uint32_t RECURSION_DATA_SIZE = 0;
uint32_t ORAM_TYPE = 0;

unsigned char *encrypted_request, *tag_in, *encrypted_response, *tag_out;
uint32_t request_size, response_size;
unsigned char *data_in;
unsigned char *data_out;
uint32_t bulk_batch_size=0;
std::string log_file;

clock_t generate_request_start, generate_request_stop, extract_response_start, extract_response_stop, process_request_start, process_request_stop, generate_request_time, extract_response_time,  process_request_time;
uint8_t Z;
FILE *iquery_file; 

///

int64_t currentTimeMillis(); 
int64_t currentTimeMicro(); 
uint32_t getRandomId();
/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

void ocall_test(const char *buffer, size_t len, const char *msg, size_t msgLen)
{
	pid = (char*)malloc(len);
	pid_msg = (char*)malloc(msgLen+1);
	memcpy(pid, buffer, len);
	memcpy(pid_msg, msg, msgLen);
	pid_msg[msgLen] = '\0';
	pidLen = len;
}
void ocall_finalise(char *msg, size_t len)
{
	char *rst = (char*)malloc(len);
	memcpy(rst, msg, len);
	printf("ocall_finalise: %s\n", rst);	
	printf("size: %d\n", len);
	printf("message in hex: ");
	for (int i = 0; i < len; i++)
		printf("%02x ", msg[i]);
}
/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to 0initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

int64_t currentTimeMillis() {
  struct timeval time;
  gettimeofday(&time, NULL);
  int64_t s1 = (int64_t)(time.tv_sec) * 1000;
  int64_t s2 = (time.tv_usec / 1000);
  return s1 + s2;
}
int64_t currentTimeMicro() {
  struct timeval time;
  gettimeofday(&time, NULL);
  int64_t s1 = (int64_t)(time.tv_sec) * 1000000;
  int64_t s2 = (time.tv_usec);
  return s1 + s2;
}
uint32_t getRandomId()
{
 	int x = 0;
	x = rand() & 0xff;
	x |= (rand() & 0xff) << 8;
	x |= (rand() & 0xff) << 16;
	x |= (rand() & 0xff) << 24;
	return (uint32_t)x;
}

int initializeZeroTrace() {
  // Variables for Enclave Public Key retrieval 
  uint32_t max_buff_size = PRIME256V1_KEY_SIZE;
  unsigned char bin_x[PRIME256V1_KEY_SIZE], bin_y[PRIME256V1_KEY_SIZE], signature_r[PRIME256V1_KEY_SIZE], signature_s[PRIME256V1_KEY_SIZE];
  
  ZT_Initialize(bin_x, bin_y, signature_r, signature_s, max_buff_size);
  
  EC_GROUP *curve;
  EC_KEY *enclave_verification_key = NULL;
  ECDSA_SIG *sig_enclave = ECDSA_SIG_new();	
  BIGNUM *x, *y, *xh, *yh, *sig_r, *sig_s;
  BN_CTX *bn_ctx = BN_CTX_new();
  int ret;

  if(NULL == (curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)))
	  printf("Setting EC_GROUP failed \n");

  EC_POINT *pub_point = EC_POINT_new(curve);
  //Verify the Enclave Public Key
  enclave_verification_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  xh = BN_bin2bn(hardcoded_verification_key_x, PRIME256V1_KEY_SIZE, NULL);
  yh = BN_bin2bn(hardcoded_verification_key_y, PRIME256V1_KEY_SIZE, NULL);
  EC_KEY_set_public_key_affine_coordinates(enclave_verification_key, xh, yh);
  unsigned char *serialized_public_key = (unsigned char*) malloc (PRIME256V1_KEY_SIZE*2);
  memcpy(serialized_public_key, bin_x, PRIME256V1_KEY_SIZE);
  memcpy(serialized_public_key + PRIME256V1_KEY_SIZE, bin_y, PRIME256V1_KEY_SIZE);
	  
  sig_enclave->r = BN_bin2bn(signature_r, PRIME256V1_KEY_SIZE, NULL);
  sig_enclave->s = BN_bin2bn(signature_s, PRIME256V1_KEY_SIZE, NULL);	
  
  ret = ECDSA_do_verify((const unsigned char*) serialized_public_key, PRIME256V1_KEY_SIZE*2, sig_enclave, enclave_verification_key);
  if(ret==1){
	  printf("GetEnclavePublishedKey : Verification Successful! \n");
  }
  else{
	  printf("GetEnclavePublishedKey : Verification FAILED! \n");
  }
  
  //Load the Enclave Public Key
  ENCLAVE_PUBLIC_KEY = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  
  x = BN_bin2bn(bin_x, PRIME256V1_KEY_SIZE, NULL);
  y = BN_bin2bn(bin_y, PRIME256V1_KEY_SIZE, NULL);
  if(EC_POINT_set_affine_coordinates_GFp(curve, pub_point, x, y, bn_ctx)==0)
	  printf("EC_POINT_set_affine_coordinates FAILED \n");

  if(EC_KEY_set_public_key(ENCLAVE_PUBLIC_KEY, pub_point)==0)
	  printf("EC_KEY_set_public_key FAILED \n");

  BN_CTX_free(bn_ctx);
  free(serialized_public_key);

}

void getParams(int argc, char* argv[])
{
  printf("Started getParams\n");
  if(argc!=NUM_EXPECTED_PARAMS) {
    printf("Command line parameters error, received: %d, expected :%d\n",
           argc, NUM_EXPECTED_PARAMS);
    printf(" <N> <No_of_requests> <Stash_size> <Data_block_size> <\"resume\"/\"new\"> <\"memory\"/\"hdd\"> <0/1 = Non-oblivious/Oblivious> <Recursion_block_size> <\"auto\"/\"path\"/\"circuit\"> <Z> <bulk_batch_size> <LogFile>\n\n");
    exit(0);
  }
  printf("argv1: %s\n", argv[1]);
  std::string str = argv[1];
  MAX_BLOCKS = std::stoi(str);
  printf("argv2: %s\n", argv[2]);
  str = argv[2];
  REQUEST_LENGTH = std::stoi(str);
  
  printf("argv3: %s\n", argv[3]);
  str = argv[3];
  STASH_SIZE = std::stoi(str);
  printf("argv4: %s\n", argv[4]);
  str = argv[4];
  DATA_SIZE = std::stoi(str);	
        str = argv[5];
  if(str=="resume")
    RESUME_EXPERIMENT = true;
  str = argv[6];
  if(str=="1")
    OBLIVIOUS_FLAG = 1;
  str = argv[7];	
  RECURSION_DATA_SIZE = std::stoi(str);

  str = argv[8];
  if(str=="path")
    ORAM_TYPE = 0;
  if(str=="circuit")
    ORAM_TYPE = 1;
  str=argv[9];
  Z = std::stoi(str);
  str=argv[10];
  bulk_batch_size = std::stoi(str);
  str = argv[11];
  log_file = str;
  std::string qfile_name = "ZT_"+std::to_string(MAX_BLOCKS)+"_"+std::to_string(DATA_SIZE);
  iquery_file = fopen(qfile_name.c_str(),"w");
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
	
	//if (argc < 2)
	//	return -1;

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
 
    /* Utilize edger8r attributes */
    //edger8r_array_attributes();
    //edger8r_pointer_attributes();
    //edger8r_type_attributes();
    //edger8r_function_attributes();
    
    /* Utilize trusted libraries */
	
	ecall_libcxx_bloom_init(100000 * 10, 0.00001);

	// Beginning to register
	int uid = -1;
	size_t AES_KEY_SIZE = 16;
	uint8_t *key = (uint8_t*)malloc(AES_KEY_SIZE);
	ecall_libcxx_sys_reg(&uid, key, AES_KEY_SIZE);
	printf("reg id: %d\n", uid);
	char *message = "Dummy Message";
	size_t msg_len = strlen(message);
	size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + msg_len + 4); 
	char *encMessage = (char *) malloc((encMessageLen+1)*sizeof(char));
	char *message_finalised = (char*)malloc(msg_len + 4);
	int uid_new = 123456;
	memcpy(message_finalised, message, msg_len);
	memcpy(message_finalised+msg_len, &uid_new, 4);
	ecall_libcxx_encrypt(message_finalised, strlen(message) + 4, encMessage, encMessageLen, uid);

	// re-encryption
	size_t encPidLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + 32 + strlen(message));
	char *encPid = (char*)malloc(encPidLen);
	ecall_libcxx_message_posting(encMessage, encMessageLen, msg_len+4, encPid, encPidLen, uid);		
	
	//
	size_t pid_len = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + 32); 
	char *pid = (char*)malloc(pid_len);
	memcpy(pid, encPid, pid_len);
	char *msg_from_enclave = (char*)malloc(msg_len + 1);
	memcpy(msg_from_enclave, encPid + pid_len, msg_len);
	msg_from_enclave[msg_len+1] = '\0';
	// printf("after msg posting: msg: %s\n", msg_from_enclave);
	
	char *tmp_pid = (char*)malloc(32);
	ecall_libcxx_decrypt(pid, pid_len, tmp_pid, 32, uid_new);
	printf("tmp_pid: %s\n", tmp_pid);
	
	// Feedback 
	char response = '1';
	int newId = 123457;
	size_t feedback_len = 1 + msg_len + pid_len + sizeof(int);
	char *feedback = (char*)malloc(feedback_len);
	feedback[0] = response;
	memcpy(feedback+1, message, msg_len);
	memcpy(feedback+1+msg_len, pid, pid_len);
	memcpy(feedback+1+msg_len+pid_len, &newId, 4);
	printf("Feedback:: %s\n", feedback);
	
	size_t enc_feedback_len = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + feedback_len);
	char *enc_feedback = (char*)malloc(enc_feedback_len);
	ecall_libcxx_encrypt(feedback, feedback_len, enc_feedback, enc_feedback_len, uid_new);

	ecall_libcxx_feedback(enc_feedback, enc_feedback_len, feedback_len, msg_len, uid_new);
//	ecall_libcxx_decrypt(msg.pid, msg.pidLen, testingdecryption, msg.msgLen+16);
	char *plainmsg = (char*)malloc(msg_len+5);
	ecall_libcxx_decrypt(encMessage, encMessageLen, plainmsg, msg_len+4, uid_new);
	plainmsg[msg_len+5] = '\0';
	printf("dec msg: %s\n", plainmsg);

	return 0;
	int64_t ms_start = 0;
	int64_t ms_end = 0;
	int num = 2000000;	
	// bloom filter
	ecall_libcxx_map_init();
	ms_start = currentTimeMillis();
	// ecall_libcxx_random_get(num);
	ms_end = currentTimeMillis();
	printf("Time spent on hashing element %d times is %d\n", num, (ms_end-ms_start));
	// ecall_libcxx_bloom_check("12\n", 2);	
	// ecall_libcxx_bloom_add("buffer\n", 6);
	// end of bloom filter
	// ========== Beginning of AES ========== //   
	int userId = 1952;

	// char *message = "Dummy Message12346";
	// ecall_libcxx_registerUser(userId);
	// size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + strlen(message)); 
	// char *encMessage = (char *) malloc((encMessageLen+1)*sizeof(char));
	// The encrypted message will contain the MAC, the IV, and the encrypted message itself.
	// ecall_libcxx_encrypt(message, strlen(message), encMessage, encMessageLen, userId);
	// encMessage[encMessageLen] = '\0';
	// printf("Encrypted message: %s\n", encMessage);

	// printf("Sending message to Enclave using ECALL.\n");
	
	
	size_t decMessageLen = strlen(message);
	char *decMessage = (char *) malloc((decMessageLen+1)*sizeof(char));

	ecall_libcxx_random_get(100);

	// printf("Decrypting...\n");
	ms_start = currentTimeMicro();
	ecall_libcxx_reEncryption(decMessageLen, encMessage, encMessageLen, decMessage, decMessageLen, userId);
	ms_end = currentTimeMicro();
	printf("time spent on reEncryption: %d\n", ms_end - ms_start);
	Message msg = {
		1,
		pid_msg,
		strlen(pid_msg),
		pid,
		pidLen
	};	
	printf("sizeof Message = %d\nReaction: %d\nMessage: %s\nMessage Length: %d\nPid: %s\nPid Length: %d\n", sizeof(msg), msg.reaction, msg.message, msg.msgLen, msg.pid, msg.pidLen);
	
//	char *testingdecryption = (char*)malloc(msg.pidLen);
//	ecall_libcxx_decrypt(msg.pid, msg.pidLen, testingdecryption, msg.msgLen+16);
//	testingdecryption[msg.pidLen] = '\0';
//	printf("testingdecryption: %s\n", testingdecryption);
	// ecall_libcxx_decrypt_with_key(encMessage,encMessageLen,decMessage,decMessageLen, new_key, 16);
	decMessage[decMessageLen] = '\0';
//	printf("Decrypted message: %s\n", decMessage);
	// ========== End of AES ========== //   

	
	// now we have pid and message from encalve, users may want to 
	// make some comments about a message from someone
	size_t size = msg.msgLen+msg.pidLen+6;
	char *comment = (char*)malloc(size);
	char *beginning = comment;
	char *newCommenterId = "99999";
	comment[0] = (char)msg.reaction + '0';
	comment++;
	memcpy(comment, msg.message, msg.msgLen);
	// comment += msg.msgLen;
	memcpy(comment + msg.msgLen, msg.pid, msg.pidLen);
	memcpy(comment + msg.msgLen + msg.pidLen, newCommenterId, 5);
// 	comment[size] = '\0';
	comment = beginning;

	printf("things to be encrypted: %s\n", comment);
	size_t encCommentLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + size); 
	char *encComment = (char *) malloc((encCommentLen+1)*sizeof(char));
	ecall_libcxx_encrypt(comment, size, encComment, encCommentLen, 99998);
	encComment[encCommentLen] = '\0';
	// printf("encrypted comment: %s\n", encComment);
	
	ecall_libcxx_random_get(100);
	ms_start = currentTimeMicro();
	ecall_libcxx_makeComment(encComment, encCommentLen, size, msg.msgLen, 99998);
	ms_end = currentTimeMicro();

	printf("time spent on making comment: %d\n", ms_end - ms_start);
	// =================
	//char *msgOut = (char*)malloc(16 * sizeof(char));
	//char *msg1 = "Dummy Message";
	//size_t msgLen = strlen(msg1);
	//size_t msgOutLen;
	// ecall_libcxx_md5(msg1, msgLen, msgOut, &msgOutLen);	
	//for (int i = 0; i < msgOutLen; i++)
	//	printf("%02x ", msgOut[i]);
	//free(msgOut);
	// =================
	sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");

    return 0;
}

