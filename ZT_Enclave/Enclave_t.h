#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _struct_foo_t
#define _struct_foo_t
typedef struct struct_foo_t {
	uint32_t struct_foo_0;
	uint64_t struct_foo_1;
} struct_foo_t;
#endif

typedef enum enum_foo_t {
	ENUM_FOO_0 = 0,
	ENUM_FOO_1 = 1,
} enum_foo_t;

#ifndef _union_foo_t
#define _union_foo_t
typedef union union_foo_t {
	uint32_t union_foo_0;
	uint32_t union_foo_1;
	uint64_t union_foo_3;
} union_foo_t;
#endif

uint32_t getNewORAMInstanceID(uint8_t oram_type);
uint8_t createNewORAMInstance(uint32_t instance_id, uint32_t maxBlocks, uint32_t dataSize, uint32_t stashSize, uint32_t oblivious_flag, uint32_t recursion_data_size, int8_t recursion_levels, uint8_t oram_type, uint8_t pZ);
uint32_t createNewLSORAMInstance(uint32_t key_size, uint32_t value_size, uint32_t num_blocks, uint8_t mem_mode, uint8_t oblivious_type, uint8_t dummy_populate);
void accessInterface(uint32_t instance_id, uint8_t oram_type, unsigned char* encrypted_request, unsigned char* encrypted_response, unsigned char* tag_in, unsigned char* tag_out, uint32_t request_size, uint32_t response_size, uint32_t tag_size);
void accessBulkReadInterface(uint32_t instance_id, uint8_t oram_type, uint32_t no_of_requests, unsigned char* encrypted_request, unsigned char* encrypted_response, unsigned char* tag_in, unsigned char* tag_out, uint32_t request_size, uint32_t response_size, uint32_t tag_size);
int8_t InitializeKeys(unsigned char* bin_x, unsigned char* bin_y, unsigned char* bin_r, unsigned char* bin_s, uint32_t size_bin);
int8_t LSORAMInsert(uint32_t instance_id, unsigned char* encrypted_request, uint32_t request_size, unsigned char* tag_in, uint32_t tag_size, unsigned char* client_pubkey, uint32_t pubkey_size, uint32_t pubkey_size_x, uint32_t pubkey_size_y);
int8_t LSORAMInsert_pt(uint32_t instance_id, unsigned char* key, uint32_t key_size, unsigned char* value, uint32_t value_size);
int8_t LSORAMFetch(uint32_t instance_id, unsigned char* encrypted_request, uint32_t request_size, unsigned char* encrypted_response, uint32_t response_size, unsigned char* tag_in, unsigned char* tag_out, uint32_t tag_size, unsigned char* client_pubkey, uint32_t pubkey_size, uint32_t pubkey_size_x, uint32_t pubkey_size_y);
int8_t HSORAMInsert(uint32_t lsoram_iid, uint32_t oram_iid, uint8_t oram_type, uint64_t oram_index, unsigned char* encrypted_request, uint32_t request_size, unsigned char* tag_in, uint32_t tag_size, unsigned char* client_pubkey, uint32_t pubkey_size, uint32_t pubkey_size_x, uint32_t pubkey_size_y);
int8_t HSORAMFetch(uint32_t lsoram_iid, uint32_t oram_iid, uint8_t oram_type, unsigned char* encrypted_request, uint32_t request_size, unsigned char* encrypted_response, uint32_t response_size, unsigned char* tag_in, unsigned char* tag_out, uint32_t tag_size, unsigned char* client_pubkey, uint32_t pubkey_size, uint32_t pubkey_size_x, uint32_t pubkey_size_y);
int8_t LSORAMEvict(uint32_t instance_id, unsigned char* key, uint32_t key_size);
uint8_t deleteLSORAMInstance(uint32_t instance_id);
void ecall_type_char(char val);
void ecall_type_int(int val);
void ecall_type_float(float val);
void ecall_type_double(double val);
void ecall_type_size_t(size_t val);
void ecall_type_wchar_t(wchar_t val);
void ecall_type_struct(struct struct_foo_t val);
void ecall_type_enum_union(enum enum_foo_t val1, union union_foo_t* val2);
size_t ecall_pointer_user_check(void* val, size_t sz);
void ecall_pointer_in(int* val);
void ecall_pointer_out(int* val);
void ecall_pointer_in_out(int* val);
void ecall_pointer_string(char* str);
void ecall_pointer_string_const(const char* str);
void ecall_pointer_size(void* ptr, size_t len);
void ecall_pointer_count(int* arr, int cnt);
void ecall_pointer_isptr_readonly(buffer_t buf, size_t len);
void ocall_pointer_attr(void);
void ecall_array_user_check(int arr[4]);
void ecall_array_in(int arr[4]);
void ecall_array_out(int arr[4]);
void ecall_array_in_out(int arr[4]);
void ecall_array_isary(array_t arr);
void ecall_function_calling_convs(void);
void ecall_function_public(void);
int ecall_function_private(void);
void ecall_malloc_free(void);
void ecall_sgx_cpuid(int cpuinfo[4], int leaf);
void ecall_exception(void);
void ecall_map(void);
size_t ecall_increase_counter(void);
void ecall_producer(void);
void ecall_consumer(void);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL getOutsidePtr_OCALL(unsigned char** retval);
sgx_status_t SGX_CDECL myprintf(char* buffer, uint32_t buffer_size);
sgx_status_t SGX_CDECL createLSORAM_OCALL(void** retval, uint32_t id, uint32_t key_size, uint32_t value_size, uint32_t num_blocks_p, uint8_t oblv_mode);
sgx_status_t SGX_CDECL build_fetchChildHash(uint32_t instance_id, uint8_t oram_type, uint32_t left, uint32_t right, unsigned char* lchild, unsigned char* rchild, uint32_t hash_size, uint32_t recursion_level);
sgx_status_t SGX_CDECL uploadBucket_OCALL(uint8_t* retval, uint32_t instance_id, uint8_t oram_type, unsigned char* serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char* hash, uint32_t hash_size, uint32_t size_for_level, uint8_t recursion_level);
sgx_status_t SGX_CDECL downloadBucket_OCALL(uint8_t* retval, uint32_t instance_id, uint8_t oram_type, unsigned char* serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char* hash, uint32_t hash_size, uint32_t size_for_level, uint8_t level);
sgx_status_t SGX_CDECL downloadPath_OCALL(uint8_t* retval, uint32_t instance_id, uint8_t oram_type, unsigned char* serialized_path, uint32_t path_size, uint32_t label, unsigned char* path_hash, uint32_t path_hash_size, uint8_t level, uint32_t D_lev);
sgx_status_t SGX_CDECL uploadPath_OCALL(uint8_t* retval, uint32_t instance_id, uint8_t oram_type, unsigned char* serialized_path, uint32_t path_size, uint32_t label, unsigned char* path_hash, uint32_t path_hash_size, uint8_t level, uint32_t D_level);
sgx_status_t SGX_CDECL time_report(int report_type, uint8_t level);
sgx_status_t SGX_CDECL ocall_pointer_user_check(int* val);
sgx_status_t SGX_CDECL ocall_pointer_in(int* val);
sgx_status_t SGX_CDECL ocall_pointer_out(int* val);
sgx_status_t SGX_CDECL ocall_pointer_in_out(int* val);
sgx_status_t SGX_CDECL memccpy(void** retval, void* dest, const void* src, int val, size_t len);
sgx_status_t SGX_CDECL ocall_function_allow(void);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
