#ifndef STATE_GPU_H
#define STATE_GPU_H

#ifdef __cplusplus
extern "C" {
#endif

// Opaque struct to hold state data
typedef struct StateDataGPU StateDataGPU;

// Function to create a new state data container
StateDataGPU* create_state_data();

// Function to add an account to state data
void add_account(StateDataGPU* state, 
                 const char* address, 
                 const char* balance, 
                 unsigned long nonce,
                 const unsigned char* root, int root_len,
                 const unsigned char* code_hash, int code_hash_len,
                 const unsigned char* code, int code_len);

// Function to add a storage entry to the most recently added account
void add_storage_entry(StateDataGPU* state, const char* key, const char* value);

// Function to set state root
void set_state_root(StateDataGPU* state, const char* root);

// Main function to process state data on GPU
void process_state_data_gpu(StateDataGPU* state);

// Function to free memory
void free_state_data(StateDataGPU* state);

#ifdef __cplusplus
}
#endif

#endif // STATE_GPU_H