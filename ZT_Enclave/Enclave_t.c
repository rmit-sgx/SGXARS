#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_getNewORAMInstanceID_t {
	uint32_t ms_retval;
	uint8_t ms_oram_type;
} ms_getNewORAMInstanceID_t;

typedef struct ms_createNewORAMInstance_t {
	uint8_t ms_retval;
	uint32_t ms_instance_id;
	uint32_t ms_maxBlocks;
	uint32_t ms_dataSize;
	uint32_t ms_stashSize;
	uint32_t ms_oblivious_flag;
	uint32_t ms_recursion_data_size;
	int8_t ms_recursion_levels;
	uint8_t ms_oram_type;
	uint8_t ms_pZ;
} ms_createNewORAMInstance_t;

typedef struct ms_createNewLSORAMInstance_t {
	uint32_t ms_retval;
	uint32_t ms_key_size;
	uint32_t ms_value_size;
	uint32_t ms_num_blocks;
	uint8_t ms_mem_mode;
	uint8_t ms_oblivious_type;
	uint8_t ms_dummy_populate;
} ms_createNewLSORAMInstance_t;

typedef struct ms_accessInterface_t {
	uint32_t ms_instance_id;
	uint8_t ms_oram_type;
	unsigned char* ms_encrypted_request;
	unsigned char* ms_encrypted_response;
	unsigned char* ms_tag_in;
	unsigned char* ms_tag_out;
	uint32_t ms_request_size;
	uint32_t ms_response_size;
	uint32_t ms_tag_size;
} ms_accessInterface_t;

typedef struct ms_accessBulkReadInterface_t {
	uint32_t ms_instance_id;
	uint8_t ms_oram_type;
	uint32_t ms_no_of_requests;
	unsigned char* ms_encrypted_request;
	unsigned char* ms_encrypted_response;
	unsigned char* ms_tag_in;
	unsigned char* ms_tag_out;
	uint32_t ms_request_size;
	uint32_t ms_response_size;
	uint32_t ms_tag_size;
} ms_accessBulkReadInterface_t;

typedef struct ms_InitializeKeys_t {
	int8_t ms_retval;
	unsigned char* ms_bin_x;
	unsigned char* ms_bin_y;
	unsigned char* ms_bin_r;
	unsigned char* ms_bin_s;
	uint32_t ms_size_bin;
} ms_InitializeKeys_t;

typedef struct ms_LSORAMInsert_t {
	int8_t ms_retval;
	uint32_t ms_instance_id;
	unsigned char* ms_encrypted_request;
	uint32_t ms_request_size;
	unsigned char* ms_tag_in;
	uint32_t ms_tag_size;
	unsigned char* ms_client_pubkey;
	uint32_t ms_pubkey_size;
	uint32_t ms_pubkey_size_x;
	uint32_t ms_pubkey_size_y;
} ms_LSORAMInsert_t;

typedef struct ms_LSORAMInsert_pt_t {
	int8_t ms_retval;
	uint32_t ms_instance_id;
	unsigned char* ms_key;
	uint32_t ms_key_size;
	unsigned char* ms_value;
	uint32_t ms_value_size;
} ms_LSORAMInsert_pt_t;

typedef struct ms_LSORAMFetch_t {
	int8_t ms_retval;
	uint32_t ms_instance_id;
	unsigned char* ms_encrypted_request;
	uint32_t ms_request_size;
	unsigned char* ms_encrypted_response;
	uint32_t ms_response_size;
	unsigned char* ms_tag_in;
	unsigned char* ms_tag_out;
	uint32_t ms_tag_size;
	unsigned char* ms_client_pubkey;
	uint32_t ms_pubkey_size;
	uint32_t ms_pubkey_size_x;
	uint32_t ms_pubkey_size_y;
} ms_LSORAMFetch_t;

typedef struct ms_HSORAMInsert_t {
	int8_t ms_retval;
	uint32_t ms_lsoram_iid;
	uint32_t ms_oram_iid;
	uint8_t ms_oram_type;
	uint64_t ms_oram_index;
	unsigned char* ms_encrypted_request;
	uint32_t ms_request_size;
	unsigned char* ms_tag_in;
	uint32_t ms_tag_size;
	unsigned char* ms_client_pubkey;
	uint32_t ms_pubkey_size;
	uint32_t ms_pubkey_size_x;
	uint32_t ms_pubkey_size_y;
} ms_HSORAMInsert_t;

typedef struct ms_HSORAMFetch_t {
	int8_t ms_retval;
	uint32_t ms_lsoram_iid;
	uint32_t ms_oram_iid;
	uint8_t ms_oram_type;
	unsigned char* ms_encrypted_request;
	uint32_t ms_request_size;
	unsigned char* ms_encrypted_response;
	uint32_t ms_response_size;
	unsigned char* ms_tag_in;
	unsigned char* ms_tag_out;
	uint32_t ms_tag_size;
	unsigned char* ms_client_pubkey;
	uint32_t ms_pubkey_size;
	uint32_t ms_pubkey_size_x;
	uint32_t ms_pubkey_size_y;
} ms_HSORAMFetch_t;

typedef struct ms_LSORAMEvict_t {
	int8_t ms_retval;
	uint32_t ms_instance_id;
	unsigned char* ms_key;
	uint32_t ms_key_size;
} ms_LSORAMEvict_t;

typedef struct ms_deleteLSORAMInstance_t {
	uint8_t ms_retval;
	uint32_t ms_instance_id;
} ms_deleteLSORAMInstance_t;

typedef struct ms_ecall_type_char_t {
	char ms_val;
} ms_ecall_type_char_t;

typedef struct ms_ecall_type_int_t {
	int ms_val;
} ms_ecall_type_int_t;

typedef struct ms_ecall_type_float_t {
	float ms_val;
} ms_ecall_type_float_t;

typedef struct ms_ecall_type_double_t {
	double ms_val;
} ms_ecall_type_double_t;

typedef struct ms_ecall_type_size_t_t {
	size_t ms_val;
} ms_ecall_type_size_t_t;

typedef struct ms_ecall_type_wchar_t_t {
	wchar_t ms_val;
} ms_ecall_type_wchar_t_t;

typedef struct ms_ecall_type_struct_t {
	struct struct_foo_t ms_val;
} ms_ecall_type_struct_t;

typedef struct ms_ecall_type_enum_union_t {
	enum enum_foo_t ms_val1;
	union union_foo_t* ms_val2;
} ms_ecall_type_enum_union_t;

typedef struct ms_ecall_pointer_user_check_t {
	size_t ms_retval;
	void* ms_val;
	size_t ms_sz;
} ms_ecall_pointer_user_check_t;

typedef struct ms_ecall_pointer_in_t {
	int* ms_val;
} ms_ecall_pointer_in_t;

typedef struct ms_ecall_pointer_out_t {
	int* ms_val;
} ms_ecall_pointer_out_t;

typedef struct ms_ecall_pointer_in_out_t {
	int* ms_val;
} ms_ecall_pointer_in_out_t;

typedef struct ms_ecall_pointer_string_t {
	char* ms_str;
	size_t ms_str_len;
} ms_ecall_pointer_string_t;

typedef struct ms_ecall_pointer_string_const_t {
	const char* ms_str;
	size_t ms_str_len;
} ms_ecall_pointer_string_const_t;

typedef struct ms_ecall_pointer_size_t {
	void* ms_ptr;
	size_t ms_len;
} ms_ecall_pointer_size_t;

typedef struct ms_ecall_pointer_count_t {
	int* ms_arr;
	int ms_cnt;
} ms_ecall_pointer_count_t;

typedef struct ms_ecall_pointer_isptr_readonly_t {
	buffer_t ms_buf;
	size_t ms_len;
} ms_ecall_pointer_isptr_readonly_t;

typedef struct ms_ecall_array_user_check_t {
	int* ms_arr;
} ms_ecall_array_user_check_t;

typedef struct ms_ecall_array_in_t {
	int* ms_arr;
} ms_ecall_array_in_t;

typedef struct ms_ecall_array_out_t {
	int* ms_arr;
} ms_ecall_array_out_t;

typedef struct ms_ecall_array_in_out_t {
	int* ms_arr;
} ms_ecall_array_in_out_t;

typedef struct ms_ecall_array_isary_t {
	array_t*  ms_arr;
} ms_ecall_array_isary_t;

typedef struct ms_ecall_function_private_t {
	int ms_retval;
} ms_ecall_function_private_t;

typedef struct ms_ecall_sgx_cpuid_t {
	int* ms_cpuinfo;
	int ms_leaf;
} ms_ecall_sgx_cpuid_t;

typedef struct ms_ecall_increase_counter_t {
	size_t ms_retval;
} ms_ecall_increase_counter_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_getOutsidePtr_OCALL_t {
	unsigned char* ms_retval;
} ms_getOutsidePtr_OCALL_t;

typedef struct ms_myprintf_t {
	char* ms_buffer;
	uint32_t ms_buffer_size;
} ms_myprintf_t;

typedef struct ms_createLSORAM_OCALL_t {
	void* ms_retval;
	uint32_t ms_id;
	uint32_t ms_key_size;
	uint32_t ms_value_size;
	uint32_t ms_num_blocks_p;
	uint8_t ms_oblv_mode;
} ms_createLSORAM_OCALL_t;

typedef struct ms_build_fetchChildHash_t {
	uint32_t ms_instance_id;
	uint8_t ms_oram_type;
	uint32_t ms_left;
	uint32_t ms_right;
	unsigned char* ms_lchild;
	unsigned char* ms_rchild;
	uint32_t ms_hash_size;
	uint32_t ms_recursion_level;
} ms_build_fetchChildHash_t;

typedef struct ms_uploadBucket_OCALL_t {
	uint8_t ms_retval;
	uint32_t ms_instance_id;
	uint8_t ms_oram_type;
	unsigned char* ms_serialized_bucket;
	uint32_t ms_bucket_size;
	uint32_t ms_label;
	unsigned char* ms_hash;
	uint32_t ms_hash_size;
	uint32_t ms_size_for_level;
	uint8_t ms_recursion_level;
} ms_uploadBucket_OCALL_t;

typedef struct ms_downloadBucket_OCALL_t {
	uint8_t ms_retval;
	uint32_t ms_instance_id;
	uint8_t ms_oram_type;
	unsigned char* ms_serialized_bucket;
	uint32_t ms_bucket_size;
	uint32_t ms_label;
	unsigned char* ms_hash;
	uint32_t ms_hash_size;
	uint32_t ms_size_for_level;
	uint8_t ms_level;
} ms_downloadBucket_OCALL_t;

typedef struct ms_downloadPath_OCALL_t {
	uint8_t ms_retval;
	uint32_t ms_instance_id;
	uint8_t ms_oram_type;
	unsigned char* ms_serialized_path;
	uint32_t ms_path_size;
	uint32_t ms_label;
	unsigned char* ms_path_hash;
	uint32_t ms_path_hash_size;
	uint8_t ms_level;
	uint32_t ms_D_lev;
} ms_downloadPath_OCALL_t;

typedef struct ms_uploadPath_OCALL_t {
	uint8_t ms_retval;
	uint32_t ms_instance_id;
	uint8_t ms_oram_type;
	unsigned char* ms_serialized_path;
	uint32_t ms_path_size;
	uint32_t ms_label;
	unsigned char* ms_path_hash;
	uint32_t ms_path_hash_size;
	uint8_t ms_level;
	uint32_t ms_D_level;
} ms_uploadPath_OCALL_t;

typedef struct ms_time_report_t {
	int ms_report_type;
	uint8_t ms_level;
} ms_time_report_t;

typedef struct ms_ocall_pointer_user_check_t {
	int* ms_val;
} ms_ocall_pointer_user_check_t;

typedef struct ms_ocall_pointer_in_t {
	int* ms_val;
} ms_ocall_pointer_in_t;

typedef struct ms_ocall_pointer_out_t {
	int* ms_val;
} ms_ocall_pointer_out_t;

typedef struct ms_ocall_pointer_in_out_t {
	int* ms_val;
} ms_ocall_pointer_in_out_t;

typedef struct ms_memccpy_t {
	void* ms_retval;
	void* ms_dest;
	const void* ms_src;
	int ms_val;
	size_t ms_len;
} ms_memccpy_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL sgx_getNewORAMInstanceID(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_getNewORAMInstanceID_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_getNewORAMInstanceID_t* ms = SGX_CAST(ms_getNewORAMInstanceID_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = getNewORAMInstanceID(ms->ms_oram_type);


	return status;
}

static sgx_status_t SGX_CDECL sgx_createNewORAMInstance(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_createNewORAMInstance_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_createNewORAMInstance_t* ms = SGX_CAST(ms_createNewORAMInstance_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = createNewORAMInstance(ms->ms_instance_id, ms->ms_maxBlocks, ms->ms_dataSize, ms->ms_stashSize, ms->ms_oblivious_flag, ms->ms_recursion_data_size, ms->ms_recursion_levels, ms->ms_oram_type, ms->ms_pZ);


	return status;
}

static sgx_status_t SGX_CDECL sgx_createNewLSORAMInstance(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_createNewLSORAMInstance_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_createNewLSORAMInstance_t* ms = SGX_CAST(ms_createNewLSORAMInstance_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = createNewLSORAMInstance(ms->ms_key_size, ms->ms_value_size, ms->ms_num_blocks, ms->ms_mem_mode, ms->ms_oblivious_type, ms->ms_dummy_populate);


	return status;
}

static sgx_status_t SGX_CDECL sgx_accessInterface(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_accessInterface_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_accessInterface_t* ms = SGX_CAST(ms_accessInterface_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_encrypted_request = ms->ms_encrypted_request;
	uint32_t _tmp_request_size = ms->ms_request_size;
	size_t _len_encrypted_request = _tmp_request_size;
	unsigned char* _in_encrypted_request = NULL;
	unsigned char* _tmp_encrypted_response = ms->ms_encrypted_response;
	uint32_t _tmp_response_size = ms->ms_response_size;
	size_t _len_encrypted_response = _tmp_response_size;
	unsigned char* _in_encrypted_response = NULL;
	unsigned char* _tmp_tag_in = ms->ms_tag_in;
	uint32_t _tmp_tag_size = ms->ms_tag_size;
	size_t _len_tag_in = _tmp_tag_size;
	unsigned char* _in_tag_in = NULL;
	unsigned char* _tmp_tag_out = ms->ms_tag_out;
	size_t _len_tag_out = _tmp_tag_size;
	unsigned char* _in_tag_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_encrypted_request, _len_encrypted_request);
	CHECK_UNIQUE_POINTER(_tmp_encrypted_response, _len_encrypted_response);
	CHECK_UNIQUE_POINTER(_tmp_tag_in, _len_tag_in);
	CHECK_UNIQUE_POINTER(_tmp_tag_out, _len_tag_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_encrypted_request != NULL && _len_encrypted_request != 0) {
		if ( _len_encrypted_request % sizeof(*_tmp_encrypted_request) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_encrypted_request = (unsigned char*)malloc(_len_encrypted_request);
		if (_in_encrypted_request == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encrypted_request, _len_encrypted_request, _tmp_encrypted_request, _len_encrypted_request)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_encrypted_response != NULL && _len_encrypted_response != 0) {
		if ( _len_encrypted_response % sizeof(*_tmp_encrypted_response) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_encrypted_response = (unsigned char*)malloc(_len_encrypted_response)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_encrypted_response, 0, _len_encrypted_response);
	}
	if (_tmp_tag_in != NULL && _len_tag_in != 0) {
		if ( _len_tag_in % sizeof(*_tmp_tag_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tag_in = (unsigned char*)malloc(_len_tag_in);
		if (_in_tag_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tag_in, _len_tag_in, _tmp_tag_in, _len_tag_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_tag_out != NULL && _len_tag_out != 0) {
		if ( _len_tag_out % sizeof(*_tmp_tag_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_tag_out = (unsigned char*)malloc(_len_tag_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_tag_out, 0, _len_tag_out);
	}

	accessInterface(ms->ms_instance_id, ms->ms_oram_type, _in_encrypted_request, _in_encrypted_response, _in_tag_in, _in_tag_out, _tmp_request_size, _tmp_response_size, _tmp_tag_size);
	if (_in_encrypted_response) {
		if (memcpy_s(_tmp_encrypted_response, _len_encrypted_response, _in_encrypted_response, _len_encrypted_response)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_tag_out) {
		if (memcpy_s(_tmp_tag_out, _len_tag_out, _in_tag_out, _len_tag_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_encrypted_request) free(_in_encrypted_request);
	if (_in_encrypted_response) free(_in_encrypted_response);
	if (_in_tag_in) free(_in_tag_in);
	if (_in_tag_out) free(_in_tag_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_accessBulkReadInterface(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_accessBulkReadInterface_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_accessBulkReadInterface_t* ms = SGX_CAST(ms_accessBulkReadInterface_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_encrypted_request = ms->ms_encrypted_request;
	uint32_t _tmp_request_size = ms->ms_request_size;
	size_t _len_encrypted_request = _tmp_request_size;
	unsigned char* _in_encrypted_request = NULL;
	unsigned char* _tmp_encrypted_response = ms->ms_encrypted_response;
	uint32_t _tmp_response_size = ms->ms_response_size;
	size_t _len_encrypted_response = _tmp_response_size;
	unsigned char* _in_encrypted_response = NULL;
	unsigned char* _tmp_tag_in = ms->ms_tag_in;
	uint32_t _tmp_tag_size = ms->ms_tag_size;
	size_t _len_tag_in = _tmp_tag_size;
	unsigned char* _in_tag_in = NULL;
	unsigned char* _tmp_tag_out = ms->ms_tag_out;
	size_t _len_tag_out = _tmp_tag_size;
	unsigned char* _in_tag_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_encrypted_request, _len_encrypted_request);
	CHECK_UNIQUE_POINTER(_tmp_encrypted_response, _len_encrypted_response);
	CHECK_UNIQUE_POINTER(_tmp_tag_in, _len_tag_in);
	CHECK_UNIQUE_POINTER(_tmp_tag_out, _len_tag_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_encrypted_request != NULL && _len_encrypted_request != 0) {
		if ( _len_encrypted_request % sizeof(*_tmp_encrypted_request) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_encrypted_request = (unsigned char*)malloc(_len_encrypted_request);
		if (_in_encrypted_request == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encrypted_request, _len_encrypted_request, _tmp_encrypted_request, _len_encrypted_request)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_encrypted_response != NULL && _len_encrypted_response != 0) {
		if ( _len_encrypted_response % sizeof(*_tmp_encrypted_response) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_encrypted_response = (unsigned char*)malloc(_len_encrypted_response)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_encrypted_response, 0, _len_encrypted_response);
	}
	if (_tmp_tag_in != NULL && _len_tag_in != 0) {
		if ( _len_tag_in % sizeof(*_tmp_tag_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tag_in = (unsigned char*)malloc(_len_tag_in);
		if (_in_tag_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tag_in, _len_tag_in, _tmp_tag_in, _len_tag_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_tag_out != NULL && _len_tag_out != 0) {
		if ( _len_tag_out % sizeof(*_tmp_tag_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_tag_out = (unsigned char*)malloc(_len_tag_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_tag_out, 0, _len_tag_out);
	}

	accessBulkReadInterface(ms->ms_instance_id, ms->ms_oram_type, ms->ms_no_of_requests, _in_encrypted_request, _in_encrypted_response, _in_tag_in, _in_tag_out, _tmp_request_size, _tmp_response_size, _tmp_tag_size);
	if (_in_encrypted_response) {
		if (memcpy_s(_tmp_encrypted_response, _len_encrypted_response, _in_encrypted_response, _len_encrypted_response)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_tag_out) {
		if (memcpy_s(_tmp_tag_out, _len_tag_out, _in_tag_out, _len_tag_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_encrypted_request) free(_in_encrypted_request);
	if (_in_encrypted_response) free(_in_encrypted_response);
	if (_in_tag_in) free(_in_tag_in);
	if (_in_tag_out) free(_in_tag_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_InitializeKeys(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_InitializeKeys_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_InitializeKeys_t* ms = SGX_CAST(ms_InitializeKeys_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_bin_x = ms->ms_bin_x;
	uint32_t _tmp_size_bin = ms->ms_size_bin;
	size_t _len_bin_x = _tmp_size_bin;
	unsigned char* _in_bin_x = NULL;
	unsigned char* _tmp_bin_y = ms->ms_bin_y;
	size_t _len_bin_y = _tmp_size_bin;
	unsigned char* _in_bin_y = NULL;
	unsigned char* _tmp_bin_r = ms->ms_bin_r;
	size_t _len_bin_r = _tmp_size_bin;
	unsigned char* _in_bin_r = NULL;
	unsigned char* _tmp_bin_s = ms->ms_bin_s;
	size_t _len_bin_s = _tmp_size_bin;
	unsigned char* _in_bin_s = NULL;

	CHECK_UNIQUE_POINTER(_tmp_bin_x, _len_bin_x);
	CHECK_UNIQUE_POINTER(_tmp_bin_y, _len_bin_y);
	CHECK_UNIQUE_POINTER(_tmp_bin_r, _len_bin_r);
	CHECK_UNIQUE_POINTER(_tmp_bin_s, _len_bin_s);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_bin_x != NULL && _len_bin_x != 0) {
		if ( _len_bin_x % sizeof(*_tmp_bin_x) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_bin_x = (unsigned char*)malloc(_len_bin_x)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_bin_x, 0, _len_bin_x);
	}
	if (_tmp_bin_y != NULL && _len_bin_y != 0) {
		if ( _len_bin_y % sizeof(*_tmp_bin_y) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_bin_y = (unsigned char*)malloc(_len_bin_y)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_bin_y, 0, _len_bin_y);
	}
	if (_tmp_bin_r != NULL && _len_bin_r != 0) {
		if ( _len_bin_r % sizeof(*_tmp_bin_r) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_bin_r = (unsigned char*)malloc(_len_bin_r)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_bin_r, 0, _len_bin_r);
	}
	if (_tmp_bin_s != NULL && _len_bin_s != 0) {
		if ( _len_bin_s % sizeof(*_tmp_bin_s) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_bin_s = (unsigned char*)malloc(_len_bin_s)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_bin_s, 0, _len_bin_s);
	}

	ms->ms_retval = InitializeKeys(_in_bin_x, _in_bin_y, _in_bin_r, _in_bin_s, _tmp_size_bin);
	if (_in_bin_x) {
		if (memcpy_s(_tmp_bin_x, _len_bin_x, _in_bin_x, _len_bin_x)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_bin_y) {
		if (memcpy_s(_tmp_bin_y, _len_bin_y, _in_bin_y, _len_bin_y)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_bin_r) {
		if (memcpy_s(_tmp_bin_r, _len_bin_r, _in_bin_r, _len_bin_r)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_bin_s) {
		if (memcpy_s(_tmp_bin_s, _len_bin_s, _in_bin_s, _len_bin_s)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_bin_x) free(_in_bin_x);
	if (_in_bin_y) free(_in_bin_y);
	if (_in_bin_r) free(_in_bin_r);
	if (_in_bin_s) free(_in_bin_s);
	return status;
}

static sgx_status_t SGX_CDECL sgx_LSORAMInsert(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_LSORAMInsert_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_LSORAMInsert_t* ms = SGX_CAST(ms_LSORAMInsert_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_encrypted_request = ms->ms_encrypted_request;
	uint32_t _tmp_request_size = ms->ms_request_size;
	size_t _len_encrypted_request = _tmp_request_size;
	unsigned char* _in_encrypted_request = NULL;
	unsigned char* _tmp_tag_in = ms->ms_tag_in;
	uint32_t _tmp_tag_size = ms->ms_tag_size;
	size_t _len_tag_in = _tmp_tag_size;
	unsigned char* _in_tag_in = NULL;
	unsigned char* _tmp_client_pubkey = ms->ms_client_pubkey;
	uint32_t _tmp_pubkey_size = ms->ms_pubkey_size;
	size_t _len_client_pubkey = _tmp_pubkey_size;
	unsigned char* _in_client_pubkey = NULL;

	CHECK_UNIQUE_POINTER(_tmp_encrypted_request, _len_encrypted_request);
	CHECK_UNIQUE_POINTER(_tmp_tag_in, _len_tag_in);
	CHECK_UNIQUE_POINTER(_tmp_client_pubkey, _len_client_pubkey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_encrypted_request != NULL && _len_encrypted_request != 0) {
		if ( _len_encrypted_request % sizeof(*_tmp_encrypted_request) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_encrypted_request = (unsigned char*)malloc(_len_encrypted_request);
		if (_in_encrypted_request == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encrypted_request, _len_encrypted_request, _tmp_encrypted_request, _len_encrypted_request)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_tag_in != NULL && _len_tag_in != 0) {
		if ( _len_tag_in % sizeof(*_tmp_tag_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tag_in = (unsigned char*)malloc(_len_tag_in);
		if (_in_tag_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tag_in, _len_tag_in, _tmp_tag_in, _len_tag_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_client_pubkey != NULL && _len_client_pubkey != 0) {
		if ( _len_client_pubkey % sizeof(*_tmp_client_pubkey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_client_pubkey = (unsigned char*)malloc(_len_client_pubkey);
		if (_in_client_pubkey == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_client_pubkey, _len_client_pubkey, _tmp_client_pubkey, _len_client_pubkey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = LSORAMInsert(ms->ms_instance_id, _in_encrypted_request, _tmp_request_size, _in_tag_in, _tmp_tag_size, _in_client_pubkey, _tmp_pubkey_size, ms->ms_pubkey_size_x, ms->ms_pubkey_size_y);

err:
	if (_in_encrypted_request) free(_in_encrypted_request);
	if (_in_tag_in) free(_in_tag_in);
	if (_in_client_pubkey) free(_in_client_pubkey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_LSORAMInsert_pt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_LSORAMInsert_pt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_LSORAMInsert_pt_t* ms = SGX_CAST(ms_LSORAMInsert_pt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_key = ms->ms_key;
	uint32_t _tmp_key_size = ms->ms_key_size;
	size_t _len_key = _tmp_key_size;
	unsigned char* _in_key = NULL;
	unsigned char* _tmp_value = ms->ms_value;
	uint32_t _tmp_value_size = ms->ms_value_size;
	size_t _len_value = _tmp_value_size;
	unsigned char* _in_value = NULL;

	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);
	CHECK_UNIQUE_POINTER(_tmp_value, _len_value);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_key != NULL && _len_key != 0) {
		if ( _len_key % sizeof(*_tmp_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_key = (unsigned char*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_key, _len_key, _tmp_key, _len_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_value != NULL && _len_value != 0) {
		if ( _len_value % sizeof(*_tmp_value) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_value = (unsigned char*)malloc(_len_value);
		if (_in_value == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_value, _len_value, _tmp_value, _len_value)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = LSORAMInsert_pt(ms->ms_instance_id, _in_key, _tmp_key_size, _in_value, _tmp_value_size);

err:
	if (_in_key) free(_in_key);
	if (_in_value) free(_in_value);
	return status;
}

static sgx_status_t SGX_CDECL sgx_LSORAMFetch(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_LSORAMFetch_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_LSORAMFetch_t* ms = SGX_CAST(ms_LSORAMFetch_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_encrypted_request = ms->ms_encrypted_request;
	uint32_t _tmp_request_size = ms->ms_request_size;
	size_t _len_encrypted_request = _tmp_request_size;
	unsigned char* _in_encrypted_request = NULL;
	unsigned char* _tmp_encrypted_response = ms->ms_encrypted_response;
	uint32_t _tmp_response_size = ms->ms_response_size;
	size_t _len_encrypted_response = _tmp_response_size;
	unsigned char* _in_encrypted_response = NULL;
	unsigned char* _tmp_tag_in = ms->ms_tag_in;
	uint32_t _tmp_tag_size = ms->ms_tag_size;
	size_t _len_tag_in = _tmp_tag_size;
	unsigned char* _in_tag_in = NULL;
	unsigned char* _tmp_tag_out = ms->ms_tag_out;
	size_t _len_tag_out = _tmp_tag_size;
	unsigned char* _in_tag_out = NULL;
	unsigned char* _tmp_client_pubkey = ms->ms_client_pubkey;
	uint32_t _tmp_pubkey_size = ms->ms_pubkey_size;
	size_t _len_client_pubkey = _tmp_pubkey_size;
	unsigned char* _in_client_pubkey = NULL;

	CHECK_UNIQUE_POINTER(_tmp_encrypted_request, _len_encrypted_request);
	CHECK_UNIQUE_POINTER(_tmp_encrypted_response, _len_encrypted_response);
	CHECK_UNIQUE_POINTER(_tmp_tag_in, _len_tag_in);
	CHECK_UNIQUE_POINTER(_tmp_tag_out, _len_tag_out);
	CHECK_UNIQUE_POINTER(_tmp_client_pubkey, _len_client_pubkey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_encrypted_request != NULL && _len_encrypted_request != 0) {
		if ( _len_encrypted_request % sizeof(*_tmp_encrypted_request) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_encrypted_request = (unsigned char*)malloc(_len_encrypted_request);
		if (_in_encrypted_request == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encrypted_request, _len_encrypted_request, _tmp_encrypted_request, _len_encrypted_request)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_encrypted_response != NULL && _len_encrypted_response != 0) {
		if ( _len_encrypted_response % sizeof(*_tmp_encrypted_response) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_encrypted_response = (unsigned char*)malloc(_len_encrypted_response)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_encrypted_response, 0, _len_encrypted_response);
	}
	if (_tmp_tag_in != NULL && _len_tag_in != 0) {
		if ( _len_tag_in % sizeof(*_tmp_tag_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tag_in = (unsigned char*)malloc(_len_tag_in);
		if (_in_tag_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tag_in, _len_tag_in, _tmp_tag_in, _len_tag_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_tag_out != NULL && _len_tag_out != 0) {
		if ( _len_tag_out % sizeof(*_tmp_tag_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_tag_out = (unsigned char*)malloc(_len_tag_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_tag_out, 0, _len_tag_out);
	}
	if (_tmp_client_pubkey != NULL && _len_client_pubkey != 0) {
		if ( _len_client_pubkey % sizeof(*_tmp_client_pubkey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_client_pubkey = (unsigned char*)malloc(_len_client_pubkey);
		if (_in_client_pubkey == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_client_pubkey, _len_client_pubkey, _tmp_client_pubkey, _len_client_pubkey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = LSORAMFetch(ms->ms_instance_id, _in_encrypted_request, _tmp_request_size, _in_encrypted_response, _tmp_response_size, _in_tag_in, _in_tag_out, _tmp_tag_size, _in_client_pubkey, _tmp_pubkey_size, ms->ms_pubkey_size_x, ms->ms_pubkey_size_y);
	if (_in_encrypted_response) {
		if (memcpy_s(_tmp_encrypted_response, _len_encrypted_response, _in_encrypted_response, _len_encrypted_response)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_tag_out) {
		if (memcpy_s(_tmp_tag_out, _len_tag_out, _in_tag_out, _len_tag_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_encrypted_request) free(_in_encrypted_request);
	if (_in_encrypted_response) free(_in_encrypted_response);
	if (_in_tag_in) free(_in_tag_in);
	if (_in_tag_out) free(_in_tag_out);
	if (_in_client_pubkey) free(_in_client_pubkey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_HSORAMInsert(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_HSORAMInsert_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_HSORAMInsert_t* ms = SGX_CAST(ms_HSORAMInsert_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_encrypted_request = ms->ms_encrypted_request;
	uint32_t _tmp_request_size = ms->ms_request_size;
	size_t _len_encrypted_request = _tmp_request_size;
	unsigned char* _in_encrypted_request = NULL;
	unsigned char* _tmp_tag_in = ms->ms_tag_in;
	uint32_t _tmp_tag_size = ms->ms_tag_size;
	size_t _len_tag_in = _tmp_tag_size;
	unsigned char* _in_tag_in = NULL;
	unsigned char* _tmp_client_pubkey = ms->ms_client_pubkey;
	uint32_t _tmp_pubkey_size = ms->ms_pubkey_size;
	size_t _len_client_pubkey = _tmp_pubkey_size;
	unsigned char* _in_client_pubkey = NULL;

	CHECK_UNIQUE_POINTER(_tmp_encrypted_request, _len_encrypted_request);
	CHECK_UNIQUE_POINTER(_tmp_tag_in, _len_tag_in);
	CHECK_UNIQUE_POINTER(_tmp_client_pubkey, _len_client_pubkey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_encrypted_request != NULL && _len_encrypted_request != 0) {
		if ( _len_encrypted_request % sizeof(*_tmp_encrypted_request) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_encrypted_request = (unsigned char*)malloc(_len_encrypted_request);
		if (_in_encrypted_request == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encrypted_request, _len_encrypted_request, _tmp_encrypted_request, _len_encrypted_request)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_tag_in != NULL && _len_tag_in != 0) {
		if ( _len_tag_in % sizeof(*_tmp_tag_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tag_in = (unsigned char*)malloc(_len_tag_in);
		if (_in_tag_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tag_in, _len_tag_in, _tmp_tag_in, _len_tag_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_client_pubkey != NULL && _len_client_pubkey != 0) {
		if ( _len_client_pubkey % sizeof(*_tmp_client_pubkey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_client_pubkey = (unsigned char*)malloc(_len_client_pubkey);
		if (_in_client_pubkey == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_client_pubkey, _len_client_pubkey, _tmp_client_pubkey, _len_client_pubkey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = HSORAMInsert(ms->ms_lsoram_iid, ms->ms_oram_iid, ms->ms_oram_type, ms->ms_oram_index, _in_encrypted_request, _tmp_request_size, _in_tag_in, _tmp_tag_size, _in_client_pubkey, _tmp_pubkey_size, ms->ms_pubkey_size_x, ms->ms_pubkey_size_y);

err:
	if (_in_encrypted_request) free(_in_encrypted_request);
	if (_in_tag_in) free(_in_tag_in);
	if (_in_client_pubkey) free(_in_client_pubkey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_HSORAMFetch(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_HSORAMFetch_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_HSORAMFetch_t* ms = SGX_CAST(ms_HSORAMFetch_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_encrypted_request = ms->ms_encrypted_request;
	uint32_t _tmp_request_size = ms->ms_request_size;
	size_t _len_encrypted_request = _tmp_request_size;
	unsigned char* _in_encrypted_request = NULL;
	unsigned char* _tmp_encrypted_response = ms->ms_encrypted_response;
	uint32_t _tmp_response_size = ms->ms_response_size;
	size_t _len_encrypted_response = _tmp_response_size;
	unsigned char* _in_encrypted_response = NULL;
	unsigned char* _tmp_tag_in = ms->ms_tag_in;
	uint32_t _tmp_tag_size = ms->ms_tag_size;
	size_t _len_tag_in = _tmp_tag_size;
	unsigned char* _in_tag_in = NULL;
	unsigned char* _tmp_tag_out = ms->ms_tag_out;
	size_t _len_tag_out = _tmp_tag_size;
	unsigned char* _in_tag_out = NULL;
	unsigned char* _tmp_client_pubkey = ms->ms_client_pubkey;
	uint32_t _tmp_pubkey_size = ms->ms_pubkey_size;
	size_t _len_client_pubkey = _tmp_pubkey_size;
	unsigned char* _in_client_pubkey = NULL;

	CHECK_UNIQUE_POINTER(_tmp_encrypted_request, _len_encrypted_request);
	CHECK_UNIQUE_POINTER(_tmp_encrypted_response, _len_encrypted_response);
	CHECK_UNIQUE_POINTER(_tmp_tag_in, _len_tag_in);
	CHECK_UNIQUE_POINTER(_tmp_tag_out, _len_tag_out);
	CHECK_UNIQUE_POINTER(_tmp_client_pubkey, _len_client_pubkey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_encrypted_request != NULL && _len_encrypted_request != 0) {
		if ( _len_encrypted_request % sizeof(*_tmp_encrypted_request) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_encrypted_request = (unsigned char*)malloc(_len_encrypted_request);
		if (_in_encrypted_request == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encrypted_request, _len_encrypted_request, _tmp_encrypted_request, _len_encrypted_request)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_encrypted_response != NULL && _len_encrypted_response != 0) {
		if ( _len_encrypted_response % sizeof(*_tmp_encrypted_response) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_encrypted_response = (unsigned char*)malloc(_len_encrypted_response)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_encrypted_response, 0, _len_encrypted_response);
	}
	if (_tmp_tag_in != NULL && _len_tag_in != 0) {
		if ( _len_tag_in % sizeof(*_tmp_tag_in) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tag_in = (unsigned char*)malloc(_len_tag_in);
		if (_in_tag_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tag_in, _len_tag_in, _tmp_tag_in, _len_tag_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_tag_out != NULL && _len_tag_out != 0) {
		if ( _len_tag_out % sizeof(*_tmp_tag_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_tag_out = (unsigned char*)malloc(_len_tag_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_tag_out, 0, _len_tag_out);
	}
	if (_tmp_client_pubkey != NULL && _len_client_pubkey != 0) {
		if ( _len_client_pubkey % sizeof(*_tmp_client_pubkey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_client_pubkey = (unsigned char*)malloc(_len_client_pubkey);
		if (_in_client_pubkey == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_client_pubkey, _len_client_pubkey, _tmp_client_pubkey, _len_client_pubkey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = HSORAMFetch(ms->ms_lsoram_iid, ms->ms_oram_iid, ms->ms_oram_type, _in_encrypted_request, _tmp_request_size, _in_encrypted_response, _tmp_response_size, _in_tag_in, _in_tag_out, _tmp_tag_size, _in_client_pubkey, _tmp_pubkey_size, ms->ms_pubkey_size_x, ms->ms_pubkey_size_y);
	if (_in_encrypted_response) {
		if (memcpy_s(_tmp_encrypted_response, _len_encrypted_response, _in_encrypted_response, _len_encrypted_response)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_tag_out) {
		if (memcpy_s(_tmp_tag_out, _len_tag_out, _in_tag_out, _len_tag_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_encrypted_request) free(_in_encrypted_request);
	if (_in_encrypted_response) free(_in_encrypted_response);
	if (_in_tag_in) free(_in_tag_in);
	if (_in_tag_out) free(_in_tag_out);
	if (_in_client_pubkey) free(_in_client_pubkey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_LSORAMEvict(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_LSORAMEvict_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_LSORAMEvict_t* ms = SGX_CAST(ms_LSORAMEvict_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_key = ms->ms_key;
	uint32_t _tmp_key_size = ms->ms_key_size;
	size_t _len_key = _tmp_key_size;
	unsigned char* _in_key = NULL;

	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_key != NULL && _len_key != 0) {
		if ( _len_key % sizeof(*_tmp_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_key = (unsigned char*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_key, _len_key, _tmp_key, _len_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = LSORAMEvict(ms->ms_instance_id, _in_key, _tmp_key_size);

err:
	if (_in_key) free(_in_key);
	return status;
}

static sgx_status_t SGX_CDECL sgx_deleteLSORAMInstance(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_deleteLSORAMInstance_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_deleteLSORAMInstance_t* ms = SGX_CAST(ms_deleteLSORAMInstance_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = deleteLSORAMInstance(ms->ms_instance_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_char(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_char_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_type_char_t* ms = SGX_CAST(ms_ecall_type_char_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_type_char(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_int(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_int_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_type_int_t* ms = SGX_CAST(ms_ecall_type_int_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_type_int(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_float(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_float_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_type_float_t* ms = SGX_CAST(ms_ecall_type_float_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_type_float(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_double(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_double_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_type_double_t* ms = SGX_CAST(ms_ecall_type_double_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_type_double(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_size_t(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_size_t_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_type_size_t_t* ms = SGX_CAST(ms_ecall_type_size_t_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_type_size_t(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_wchar_t(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_wchar_t_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_type_wchar_t_t* ms = SGX_CAST(ms_ecall_type_wchar_t_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_type_wchar_t(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_struct(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_struct_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_type_struct_t* ms = SGX_CAST(ms_ecall_type_struct_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_type_struct(ms->ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_enum_union(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_enum_union_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_type_enum_union_t* ms = SGX_CAST(ms_ecall_type_enum_union_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	union union_foo_t* _tmp_val2 = ms->ms_val2;



	ecall_type_enum_union(ms->ms_val1, _tmp_val2);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_user_check(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_user_check_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_user_check_t* ms = SGX_CAST(ms_ecall_pointer_user_check_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_val = ms->ms_val;



	ms->ms_retval = ecall_pointer_user_check(_tmp_val, ms->ms_sz);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_in(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_in_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_in_t* ms = SGX_CAST(ms_ecall_pointer_in_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = ms->ms_val;
	size_t _len_val = sizeof(int);
	int* _in_val = NULL;

	CHECK_UNIQUE_POINTER(_tmp_val, _len_val);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_val != NULL && _len_val != 0) {
		if ( _len_val % sizeof(*_tmp_val) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_val = (int*)malloc(_len_val);
		if (_in_val == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_val, _len_val, _tmp_val, _len_val)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_pointer_in(_in_val);

err:
	if (_in_val) free(_in_val);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_out_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_out_t* ms = SGX_CAST(ms_ecall_pointer_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = ms->ms_val;
	size_t _len_val = sizeof(int);
	int* _in_val = NULL;

	CHECK_UNIQUE_POINTER(_tmp_val, _len_val);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_val != NULL && _len_val != 0) {
		if ( _len_val % sizeof(*_tmp_val) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_val = (int*)malloc(_len_val)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_val, 0, _len_val);
	}

	ecall_pointer_out(_in_val);
	if (_in_val) {
		if (memcpy_s(_tmp_val, _len_val, _in_val, _len_val)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_val) free(_in_val);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_in_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_in_out_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_in_out_t* ms = SGX_CAST(ms_ecall_pointer_in_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = ms->ms_val;
	size_t _len_val = sizeof(int);
	int* _in_val = NULL;

	CHECK_UNIQUE_POINTER(_tmp_val, _len_val);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_val != NULL && _len_val != 0) {
		if ( _len_val % sizeof(*_tmp_val) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_val = (int*)malloc(_len_val);
		if (_in_val == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_val, _len_val, _tmp_val, _len_val)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_pointer_in_out(_in_val);
	if (_in_val) {
		if (memcpy_s(_tmp_val, _len_val, _in_val, _len_val)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_val) free(_in_val);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_string(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_string_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_string_t* ms = SGX_CAST(ms_ecall_pointer_string_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = ms->ms_str;
	size_t _len_str = ms->ms_str_len ;
	char* _in_str = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_str != NULL && _len_str != 0) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str, _len_str, _tmp_str, _len_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str[_len_str - 1] = '\0';
		if (_len_str != strlen(_in_str) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ecall_pointer_string(_in_str);
	if (_in_str)
	{
		_in_str[_len_str - 1] = '\0';
		_len_str = strlen(_in_str) + 1;
		if (memcpy_s((void*)_tmp_str, _len_str, _in_str, _len_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_str) free(_in_str);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_string_const(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_string_const_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_string_const_t* ms = SGX_CAST(ms_ecall_pointer_string_const_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_str = ms->ms_str;
	size_t _len_str = ms->ms_str_len ;
	char* _in_str = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_str != NULL && _len_str != 0) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str, _len_str, _tmp_str, _len_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str[_len_str - 1] = '\0';
		if (_len_str != strlen(_in_str) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ecall_pointer_string_const((const char*)_in_str);

err:
	if (_in_str) free(_in_str);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_size_t* ms = SGX_CAST(ms_ecall_pointer_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_ptr = ms->ms_ptr;
	size_t _tmp_len = ms->ms_len;
	size_t _len_ptr = _tmp_len;
	void* _in_ptr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ptr, _len_ptr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ptr != NULL && _len_ptr != 0) {
		_in_ptr = (void*)malloc(_len_ptr);
		if (_in_ptr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ptr, _len_ptr, _tmp_ptr, _len_ptr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_pointer_size(_in_ptr, _tmp_len);
	if (_in_ptr) {
		if (memcpy_s(_tmp_ptr, _len_ptr, _in_ptr, _len_ptr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ptr) free(_in_ptr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_count(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_count_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_count_t* ms = SGX_CAST(ms_ecall_pointer_count_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	int _tmp_cnt = ms->ms_cnt;
	size_t _len_arr = _tmp_cnt * sizeof(int);
	int* _in_arr = NULL;

	if (sizeof(*_tmp_arr) != 0 &&
		(size_t)_tmp_cnt > (SIZE_MAX / sizeof(*_tmp_arr))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_arr != NULL && _len_arr != 0) {
		if ( _len_arr % sizeof(*_tmp_arr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_arr, _len_arr, _tmp_arr, _len_arr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_pointer_count(_in_arr, _tmp_cnt);
	if (_in_arr) {
		if (memcpy_s(_tmp_arr, _len_arr, _in_arr, _len_arr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_arr) free(_in_arr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_isptr_readonly(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_isptr_readonly_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_isptr_readonly_t* ms = SGX_CAST(ms_ecall_pointer_isptr_readonly_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	buffer_t _tmp_buf = ms->ms_buf;
	size_t _tmp_len = ms->ms_len;
	size_t _len_buf = _tmp_len;
	buffer_t _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		_in_buf = (buffer_t)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s((void*)_in_buf, _len_buf, _tmp_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_pointer_isptr_readonly(_in_buf, _tmp_len);

err:
	if (_in_buf) free((void*)_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ocall_pointer_attr(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_pointer_attr();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_user_check(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_user_check_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_array_user_check_t* ms = SGX_CAST(ms_ecall_array_user_check_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;



	ecall_array_user_check(_tmp_arr);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_in(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_in_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_array_in_t* ms = SGX_CAST(ms_ecall_array_in_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(int);
	int* _in_arr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_arr != NULL && _len_arr != 0) {
		if ( _len_arr % sizeof(*_tmp_arr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_arr, _len_arr, _tmp_arr, _len_arr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_array_in(_in_arr);

err:
	if (_in_arr) free(_in_arr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_out_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_array_out_t* ms = SGX_CAST(ms_ecall_array_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(int);
	int* _in_arr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_arr != NULL && _len_arr != 0) {
		if ( _len_arr % sizeof(*_tmp_arr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_arr = (int*)malloc(_len_arr)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_arr, 0, _len_arr);
	}

	ecall_array_out(_in_arr);
	if (_in_arr) {
		if (memcpy_s(_tmp_arr, _len_arr, _in_arr, _len_arr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_arr) free(_in_arr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_in_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_in_out_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_array_in_out_t* ms = SGX_CAST(ms_ecall_array_in_out_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = ms->ms_arr;
	size_t _len_arr = 4 * sizeof(int);
	int* _in_arr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_arr != NULL && _len_arr != 0) {
		if ( _len_arr % sizeof(*_tmp_arr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_arr, _len_arr, _tmp_arr, _len_arr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_array_in_out(_in_arr);
	if (_in_arr) {
		if (memcpy_s(_tmp_arr, _len_arr, _in_arr, _len_arr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_arr) free(_in_arr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_isary(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_isary_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_array_isary_t* ms = SGX_CAST(ms_ecall_array_isary_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_array_isary((ms->ms_arr != NULL) ? (*ms->ms_arr) : NULL);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_function_calling_convs(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_function_calling_convs();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_function_public(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_function_public();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_function_private(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_function_private_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_function_private_t* ms = SGX_CAST(ms_ecall_function_private_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_function_private();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_malloc_free(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_malloc_free();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sgx_cpuid(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sgx_cpuid_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sgx_cpuid_t* ms = SGX_CAST(ms_ecall_sgx_cpuid_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_cpuinfo = ms->ms_cpuinfo;
	size_t _len_cpuinfo = 4 * sizeof(int);
	int* _in_cpuinfo = NULL;

	CHECK_UNIQUE_POINTER(_tmp_cpuinfo, _len_cpuinfo);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_cpuinfo != NULL && _len_cpuinfo != 0) {
		if ( _len_cpuinfo % sizeof(*_tmp_cpuinfo) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_cpuinfo = (int*)malloc(_len_cpuinfo)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_cpuinfo, 0, _len_cpuinfo);
	}

	ecall_sgx_cpuid(_in_cpuinfo, ms->ms_leaf);
	if (_in_cpuinfo) {
		if (memcpy_s(_tmp_cpuinfo, _len_cpuinfo, _in_cpuinfo, _len_cpuinfo)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_cpuinfo) free(_in_cpuinfo);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_exception(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_exception();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_map(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_map();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_increase_counter(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_increase_counter_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_increase_counter_t* ms = SGX_CAST(ms_ecall_increase_counter_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_increase_counter();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_producer(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_producer();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_consumer(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_consumer();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[46];
} g_ecall_table = {
	46,
	{
		{(void*)(uintptr_t)sgx_getNewORAMInstanceID, 0, 0},
		{(void*)(uintptr_t)sgx_createNewORAMInstance, 0, 0},
		{(void*)(uintptr_t)sgx_createNewLSORAMInstance, 0, 0},
		{(void*)(uintptr_t)sgx_accessInterface, 0, 0},
		{(void*)(uintptr_t)sgx_accessBulkReadInterface, 0, 0},
		{(void*)(uintptr_t)sgx_InitializeKeys, 0, 0},
		{(void*)(uintptr_t)sgx_LSORAMInsert, 0, 0},
		{(void*)(uintptr_t)sgx_LSORAMInsert_pt, 0, 0},
		{(void*)(uintptr_t)sgx_LSORAMFetch, 0, 0},
		{(void*)(uintptr_t)sgx_HSORAMInsert, 0, 0},
		{(void*)(uintptr_t)sgx_HSORAMFetch, 0, 0},
		{(void*)(uintptr_t)sgx_LSORAMEvict, 0, 0},
		{(void*)(uintptr_t)sgx_deleteLSORAMInstance, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_type_char, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_type_int, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_type_float, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_type_double, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_type_size_t, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_type_wchar_t, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_type_struct, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_type_enum_union, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_user_check, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_in, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_out, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_in_out, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_string, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_string_const, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_size, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_count, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_isptr_readonly, 0, 0},
		{(void*)(uintptr_t)sgx_ocall_pointer_attr, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_array_user_check, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_array_in, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_array_out, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_array_in_out, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_array_isary, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_function_calling_convs, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_function_public, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_function_private, 1, 0},
		{(void*)(uintptr_t)sgx_ecall_malloc_free, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sgx_cpuid, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_exception, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_map, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_increase_counter, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_producer, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_consumer, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[21][46];
} g_dyn_entry_table = {
	21,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL getOutsidePtr_OCALL(unsigned char** retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_getOutsidePtr_OCALL_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_getOutsidePtr_OCALL_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_getOutsidePtr_OCALL_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_getOutsidePtr_OCALL_t));
	ocalloc_size -= sizeof(ms_getOutsidePtr_OCALL_t);

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL myprintf(char* buffer, uint32_t buffer_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = buffer_size;

	ms_myprintf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_myprintf_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buffer, _len_buffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buffer != NULL) ? _len_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_myprintf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_myprintf_t));
	ocalloc_size -= sizeof(ms_myprintf_t);

	if (buffer != NULL) {
		ms->ms_buffer = (char*)__tmp;
		if (_len_buffer % sizeof(*buffer) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, buffer, _len_buffer)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		ocalloc_size -= _len_buffer;
	} else {
		ms->ms_buffer = NULL;
	}
	
	ms->ms_buffer_size = buffer_size;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL createLSORAM_OCALL(void** retval, uint32_t id, uint32_t key_size, uint32_t value_size, uint32_t num_blocks_p, uint8_t oblv_mode)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_createLSORAM_OCALL_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_createLSORAM_OCALL_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_createLSORAM_OCALL_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_createLSORAM_OCALL_t));
	ocalloc_size -= sizeof(ms_createLSORAM_OCALL_t);

	ms->ms_id = id;
	ms->ms_key_size = key_size;
	ms->ms_value_size = value_size;
	ms->ms_num_blocks_p = num_blocks_p;
	ms->ms_oblv_mode = oblv_mode;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL build_fetchChildHash(uint32_t instance_id, uint8_t oram_type, uint32_t left, uint32_t right, unsigned char* lchild, unsigned char* rchild, uint32_t hash_size, uint32_t recursion_level)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_lchild = hash_size;
	size_t _len_rchild = hash_size;

	ms_build_fetchChildHash_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_build_fetchChildHash_t);
	void *__tmp = NULL;

	void *__tmp_lchild = NULL;
	void *__tmp_rchild = NULL;

	CHECK_ENCLAVE_POINTER(lchild, _len_lchild);
	CHECK_ENCLAVE_POINTER(rchild, _len_rchild);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (lchild != NULL) ? _len_lchild : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (rchild != NULL) ? _len_rchild : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_build_fetchChildHash_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_build_fetchChildHash_t));
	ocalloc_size -= sizeof(ms_build_fetchChildHash_t);

	ms->ms_instance_id = instance_id;
	ms->ms_oram_type = oram_type;
	ms->ms_left = left;
	ms->ms_right = right;
	if (lchild != NULL) {
		ms->ms_lchild = (unsigned char*)__tmp;
		__tmp_lchild = __tmp;
		if (_len_lchild % sizeof(*lchild) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_lchild, 0, _len_lchild);
		__tmp = (void *)((size_t)__tmp + _len_lchild);
		ocalloc_size -= _len_lchild;
	} else {
		ms->ms_lchild = NULL;
	}
	
	if (rchild != NULL) {
		ms->ms_rchild = (unsigned char*)__tmp;
		__tmp_rchild = __tmp;
		if (_len_rchild % sizeof(*rchild) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_rchild, 0, _len_rchild);
		__tmp = (void *)((size_t)__tmp + _len_rchild);
		ocalloc_size -= _len_rchild;
	} else {
		ms->ms_rchild = NULL;
	}
	
	ms->ms_hash_size = hash_size;
	ms->ms_recursion_level = recursion_level;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (lchild) {
			if (memcpy_s((void*)lchild, _len_lchild, __tmp_lchild, _len_lchild)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (rchild) {
			if (memcpy_s((void*)rchild, _len_rchild, __tmp_rchild, _len_rchild)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL uploadBucket_OCALL(uint8_t* retval, uint32_t instance_id, uint8_t oram_type, unsigned char* serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char* hash, uint32_t hash_size, uint32_t size_for_level, uint8_t recursion_level)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_serialized_bucket = bucket_size;
	size_t _len_hash = hash_size;

	ms_uploadBucket_OCALL_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_uploadBucket_OCALL_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(serialized_bucket, _len_serialized_bucket);
	CHECK_ENCLAVE_POINTER(hash, _len_hash);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (serialized_bucket != NULL) ? _len_serialized_bucket : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (hash != NULL) ? _len_hash : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_uploadBucket_OCALL_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_uploadBucket_OCALL_t));
	ocalloc_size -= sizeof(ms_uploadBucket_OCALL_t);

	ms->ms_instance_id = instance_id;
	ms->ms_oram_type = oram_type;
	if (serialized_bucket != NULL) {
		ms->ms_serialized_bucket = (unsigned char*)__tmp;
		if (_len_serialized_bucket % sizeof(*serialized_bucket) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, serialized_bucket, _len_serialized_bucket)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_serialized_bucket);
		ocalloc_size -= _len_serialized_bucket;
	} else {
		ms->ms_serialized_bucket = NULL;
	}
	
	ms->ms_bucket_size = bucket_size;
	ms->ms_label = label;
	if (hash != NULL) {
		ms->ms_hash = (unsigned char*)__tmp;
		if (_len_hash % sizeof(*hash) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, hash, _len_hash)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_hash);
		ocalloc_size -= _len_hash;
	} else {
		ms->ms_hash = NULL;
	}
	
	ms->ms_hash_size = hash_size;
	ms->ms_size_for_level = size_for_level;
	ms->ms_recursion_level = recursion_level;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL downloadBucket_OCALL(uint8_t* retval, uint32_t instance_id, uint8_t oram_type, unsigned char* serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char* hash, uint32_t hash_size, uint32_t size_for_level, uint8_t level)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_serialized_bucket = bucket_size;
	size_t _len_hash = hash_size;

	ms_downloadBucket_OCALL_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_downloadBucket_OCALL_t);
	void *__tmp = NULL;

	void *__tmp_serialized_bucket = NULL;
	void *__tmp_hash = NULL;

	CHECK_ENCLAVE_POINTER(serialized_bucket, _len_serialized_bucket);
	CHECK_ENCLAVE_POINTER(hash, _len_hash);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (serialized_bucket != NULL) ? _len_serialized_bucket : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (hash != NULL) ? _len_hash : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_downloadBucket_OCALL_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_downloadBucket_OCALL_t));
	ocalloc_size -= sizeof(ms_downloadBucket_OCALL_t);

	ms->ms_instance_id = instance_id;
	ms->ms_oram_type = oram_type;
	if (serialized_bucket != NULL) {
		ms->ms_serialized_bucket = (unsigned char*)__tmp;
		__tmp_serialized_bucket = __tmp;
		if (_len_serialized_bucket % sizeof(*serialized_bucket) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_serialized_bucket, 0, _len_serialized_bucket);
		__tmp = (void *)((size_t)__tmp + _len_serialized_bucket);
		ocalloc_size -= _len_serialized_bucket;
	} else {
		ms->ms_serialized_bucket = NULL;
	}
	
	ms->ms_bucket_size = bucket_size;
	ms->ms_label = label;
	if (hash != NULL) {
		ms->ms_hash = (unsigned char*)__tmp;
		__tmp_hash = __tmp;
		if (_len_hash % sizeof(*hash) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_hash, 0, _len_hash);
		__tmp = (void *)((size_t)__tmp + _len_hash);
		ocalloc_size -= _len_hash;
	} else {
		ms->ms_hash = NULL;
	}
	
	ms->ms_hash_size = hash_size;
	ms->ms_size_for_level = size_for_level;
	ms->ms_level = level;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (serialized_bucket) {
			if (memcpy_s((void*)serialized_bucket, _len_serialized_bucket, __tmp_serialized_bucket, _len_serialized_bucket)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (hash) {
			if (memcpy_s((void*)hash, _len_hash, __tmp_hash, _len_hash)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL downloadPath_OCALL(uint8_t* retval, uint32_t instance_id, uint8_t oram_type, unsigned char* serialized_path, uint32_t path_size, uint32_t label, unsigned char* path_hash, uint32_t path_hash_size, uint8_t level, uint32_t D_lev)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_serialized_path = path_size;
	size_t _len_path_hash = path_hash_size;

	ms_downloadPath_OCALL_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_downloadPath_OCALL_t);
	void *__tmp = NULL;

	void *__tmp_serialized_path = NULL;
	void *__tmp_path_hash = NULL;

	CHECK_ENCLAVE_POINTER(serialized_path, _len_serialized_path);
	CHECK_ENCLAVE_POINTER(path_hash, _len_path_hash);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (serialized_path != NULL) ? _len_serialized_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path_hash != NULL) ? _len_path_hash : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_downloadPath_OCALL_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_downloadPath_OCALL_t));
	ocalloc_size -= sizeof(ms_downloadPath_OCALL_t);

	ms->ms_instance_id = instance_id;
	ms->ms_oram_type = oram_type;
	if (serialized_path != NULL) {
		ms->ms_serialized_path = (unsigned char*)__tmp;
		__tmp_serialized_path = __tmp;
		if (_len_serialized_path % sizeof(*serialized_path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_serialized_path, 0, _len_serialized_path);
		__tmp = (void *)((size_t)__tmp + _len_serialized_path);
		ocalloc_size -= _len_serialized_path;
	} else {
		ms->ms_serialized_path = NULL;
	}
	
	ms->ms_path_size = path_size;
	ms->ms_label = label;
	if (path_hash != NULL) {
		ms->ms_path_hash = (unsigned char*)__tmp;
		__tmp_path_hash = __tmp;
		if (_len_path_hash % sizeof(*path_hash) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_path_hash, 0, _len_path_hash);
		__tmp = (void *)((size_t)__tmp + _len_path_hash);
		ocalloc_size -= _len_path_hash;
	} else {
		ms->ms_path_hash = NULL;
	}
	
	ms->ms_path_hash_size = path_hash_size;
	ms->ms_level = level;
	ms->ms_D_lev = D_lev;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (serialized_path) {
			if (memcpy_s((void*)serialized_path, _len_serialized_path, __tmp_serialized_path, _len_serialized_path)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (path_hash) {
			if (memcpy_s((void*)path_hash, _len_path_hash, __tmp_path_hash, _len_path_hash)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL uploadPath_OCALL(uint8_t* retval, uint32_t instance_id, uint8_t oram_type, unsigned char* serialized_path, uint32_t path_size, uint32_t label, unsigned char* path_hash, uint32_t path_hash_size, uint8_t level, uint32_t D_level)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_serialized_path = path_size;
	size_t _len_path_hash = path_hash_size;

	ms_uploadPath_OCALL_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_uploadPath_OCALL_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(serialized_path, _len_serialized_path);
	CHECK_ENCLAVE_POINTER(path_hash, _len_path_hash);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (serialized_path != NULL) ? _len_serialized_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path_hash != NULL) ? _len_path_hash : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_uploadPath_OCALL_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_uploadPath_OCALL_t));
	ocalloc_size -= sizeof(ms_uploadPath_OCALL_t);

	ms->ms_instance_id = instance_id;
	ms->ms_oram_type = oram_type;
	if (serialized_path != NULL) {
		ms->ms_serialized_path = (unsigned char*)__tmp;
		if (_len_serialized_path % sizeof(*serialized_path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, serialized_path, _len_serialized_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_serialized_path);
		ocalloc_size -= _len_serialized_path;
	} else {
		ms->ms_serialized_path = NULL;
	}
	
	ms->ms_path_size = path_size;
	ms->ms_label = label;
	if (path_hash != NULL) {
		ms->ms_path_hash = (unsigned char*)__tmp;
		if (_len_path_hash % sizeof(*path_hash) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, path_hash, _len_path_hash)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path_hash);
		ocalloc_size -= _len_path_hash;
	} else {
		ms->ms_path_hash = NULL;
	}
	
	ms->ms_path_hash_size = path_hash_size;
	ms->ms_level = level;
	ms->ms_D_level = D_level;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL time_report(int report_type, uint8_t level)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_time_report_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_time_report_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_time_report_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_time_report_t));
	ocalloc_size -= sizeof(ms_time_report_t);

	ms->ms_report_type = report_type;
	ms->ms_level = level;
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_user_check(int* val)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pointer_user_check_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_user_check_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_user_check_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_user_check_t));
	ocalloc_size -= sizeof(ms_ocall_pointer_user_check_t);

	ms->ms_val = val;
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_in(int* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val = sizeof(int);

	ms_ocall_pointer_in_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_in_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(val, _len_val);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (val != NULL) ? _len_val : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_in_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_in_t));
	ocalloc_size -= sizeof(ms_ocall_pointer_in_t);

	if (val != NULL) {
		ms->ms_val = (int*)__tmp;
		if (_len_val % sizeof(*val) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, val, _len_val)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_val);
		ocalloc_size -= _len_val;
	} else {
		ms->ms_val = NULL;
	}
	
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_out(int* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val = sizeof(int);

	ms_ocall_pointer_out_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_out_t);
	void *__tmp = NULL;

	void *__tmp_val = NULL;

	CHECK_ENCLAVE_POINTER(val, _len_val);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (val != NULL) ? _len_val : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_out_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_out_t));
	ocalloc_size -= sizeof(ms_ocall_pointer_out_t);

	if (val != NULL) {
		ms->ms_val = (int*)__tmp;
		__tmp_val = __tmp;
		if (_len_val % sizeof(*val) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_val, 0, _len_val);
		__tmp = (void *)((size_t)__tmp + _len_val);
		ocalloc_size -= _len_val;
	} else {
		ms->ms_val = NULL;
	}
	
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (val) {
			if (memcpy_s((void*)val, _len_val, __tmp_val, _len_val)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_in_out(int* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val = sizeof(int);

	ms_ocall_pointer_in_out_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_in_out_t);
	void *__tmp = NULL;

	void *__tmp_val = NULL;

	CHECK_ENCLAVE_POINTER(val, _len_val);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (val != NULL) ? _len_val : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_in_out_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_in_out_t));
	ocalloc_size -= sizeof(ms_ocall_pointer_in_out_t);

	if (val != NULL) {
		ms->ms_val = (int*)__tmp;
		__tmp_val = __tmp;
		if (_len_val % sizeof(*val) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, val, _len_val)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_val);
		ocalloc_size -= _len_val;
	} else {
		ms->ms_val = NULL;
	}
	
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (val) {
			if (memcpy_s((void*)val, _len_val, __tmp_val, _len_val)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL memccpy(void** retval, void* dest, const void* src, int val, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dest = len;
	size_t _len_src = len;

	ms_memccpy_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_memccpy_t);
	void *__tmp = NULL;

	void *__tmp_dest = NULL;

	CHECK_ENCLAVE_POINTER(dest, _len_dest);
	CHECK_ENCLAVE_POINTER(src, _len_src);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dest != NULL) ? _len_dest : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (src != NULL) ? _len_src : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_memccpy_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_memccpy_t));
	ocalloc_size -= sizeof(ms_memccpy_t);

	if (dest != NULL) {
		ms->ms_dest = (void*)__tmp;
		__tmp_dest = __tmp;
		if (memcpy_s(__tmp, ocalloc_size, dest, _len_dest)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_dest);
		ocalloc_size -= _len_dest;
	} else {
		ms->ms_dest = NULL;
	}
	
	if (src != NULL) {
		ms->ms_src = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, src, _len_src)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_src);
		ocalloc_size -= _len_src;
	} else {
		ms->ms_src = NULL;
	}
	
	ms->ms_val = val;
	ms->ms_len = len;
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (dest) {
			if (memcpy_s((void*)dest, _len_dest, __tmp_dest, _len_dest)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_function_allow(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(15, NULL);

	return status;
}
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

