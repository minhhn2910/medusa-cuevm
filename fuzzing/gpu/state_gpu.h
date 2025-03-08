#ifndef STATE_GPU_H
#define STATE_GPU_H

#include <stdint.h>  // Changed from <cstdint>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UINT256_WORDS 8
#define UINT256_BITS 256
#define UINT256_BYTES 32
#define UINT256_LIMBS_BYTES 4

// Compatible uint256 struct for both Go and C++
typedef struct uint256 {
    uint32_t words[UINT256_WORDS];
} uint256;

// Opaque struct to hold state data
typedef struct StateDataGPU StateDataGPU;

// Function to create a new state data container
StateDataGPU* create_state_data();

// Function to set state root from byte array
void set_state_root(StateDataGPU* state, const unsigned char* root, int root_len);

// Function to add an account to state data with byte array inputs
void add_account(StateDataGPU* state, 
                 const unsigned char* addr, int addr_len,
                 const unsigned char* balance, int balance_len,
                 unsigned long nonce,
                 const unsigned char* root, int root_len,
                 const unsigned char* code_hash, int code_hash_len,
                 const unsigned char* code, int code_len,
                 bool has_code);

// Function to add a storage entry using byte arrays
void add_storage_entry(StateDataGPU* state, 
                       const unsigned char* key, int key_len, 
                       const unsigned char* value, int value_len);

// Main function to process state data on GPU
int process_state_data_gpu(StateDataGPU* state);

// Function to free memory
void free_state_data(StateDataGPU* state);

#ifdef __cplusplus
}
#endif

#endif // STATE_GPU_H