#include "state_gpu.h"
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm> // For std::min

// Account data structure
struct Account {
    uint256 address;
    uint256 balance;
    unsigned long nonce;
    std::vector<unsigned char> root;
    std::vector<unsigned char> codeHash;
    std::vector<unsigned char> code;
    bool hasCode;
    std::vector<uint256> storageKeys;
    std::vector<uint256> storageVals;
};

// State data container
struct StateDataGPU {
    uint256 root;
    std::vector<Account> accounts;
};

// Helper function to convert byte array to uint256
void bytes_to_uint256(const unsigned char* bytes, int len, uint256& result) {
    // Initialize result to zero
    memset(&result, 0, sizeof(uint256));
    
    // Convert bytes to uint256, handling different lengths
    int copyLen = std::min(len, UINT256_BYTES);
    if (copyLen > 0) {
        // Copy from end of byte array to beginning of uint256 (big-endian to little-endian)
        for (int i = 0; i < copyLen; i++) {
            // Byte position in uint256 (little-endian)
            int pos = i % 4;
            // Word index in uint256 (little-endian)
            int word = i / 4;
            // Set the byte in the corresponding word
            result.words[word] |= (static_cast<uint32_t>(bytes[len - 1 - i]) << (pos * 8));
        }
    }
}

// Helper function to convert uint256 to hex string
std::string uint256_to_hex(const uint256& value) {
    std::stringstream ss;
    ss << "0x";
    for (int i = UINT256_WORDS - 1; i >= 0; i--) { // Start from most significant word
        ss << std::hex << std::setfill('0') << std::setw(8) << value.words[i];
    }
    return ss.str();
}

// Helper function to convert bytes to hex string
std::string bytes_to_hex(const unsigned char* data, int len) {
    std::stringstream ss;
    ss << "0x";
    for (int i = 0; i < len; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

// Create a new state data container
StateDataGPU* create_state_data() {
    return new StateDataGPU();
}

// Set state root from byte array
void set_state_root(StateDataGPU* state, const unsigned char* root, int root_len) {
    bytes_to_uint256(root, root_len, state->root);
}

// Add an account to state data with byte array inputs
void add_account(StateDataGPU* state, 
                 const unsigned char* addr, int addr_len,
                 const unsigned char* balance, int balance_len,
                 unsigned long nonce,
                 const unsigned char* root, int root_len,
                 const unsigned char* code_hash, int code_hash_len,
                 const unsigned char* code, int code_len,
                 bool has_code) {
    // Create a new account and add it to our list
    Account account;
    
    // Convert address bytes to uint256
    bytes_to_uint256(addr, addr_len, account.address);
    
    // Convert balance bytes to uint256
    bytes_to_uint256(balance, balance_len, account.balance);
    
    // Set the account nonce
    account.nonce = nonce;
    
    // Set the root if provided
    if (root != nullptr && root_len > 0) {
        account.root.resize(root_len);
        std::memcpy(account.root.data(), root, root_len);
    }
    
    // Set the code hash if provided
    if (code_hash != nullptr && code_hash_len > 0) {
        account.codeHash.resize(code_hash_len);
        std::memcpy(account.codeHash.data(), code_hash, code_hash_len);
    }
    
    // Set the code if provided
    if (code != nullptr && code_len > 0) {
        account.code.resize(code_len);
        std::memcpy(account.code.data(), code, code_len);
    }
    
    // Set whether the account has code
    account.hasCode = has_code;
    
    // Add the account to our state data
    state->accounts.push_back(account);
}

// Add a storage entry to the last added account
void add_storage_entry(StateDataGPU* state, 
                       const unsigned char* key, int key_len, 
                       const unsigned char* value, int value_len) {
    // Ensure we have at least one account
    if (state->accounts.empty()) {
        std::cerr << "Cannot add storage entry: No accounts added yet" << std::endl;
        return;
    }
    
    // Convert key bytes to uint256
    uint256 key_uint256;
    bytes_to_uint256(key, key_len, key_uint256);
    
    // Convert value bytes to uint256
    uint256 value_uint256;
    bytes_to_uint256(value, value_len, value_uint256);
    
    // Add to the last account's storage
    state->accounts.back().storageKeys.push_back(key_uint256);
    state->accounts.back().storageVals.push_back(value_uint256);
}

// Process state data on GPU
int process_state_data_gpu(StateDataGPU* state) {
    std::cout << "Processing state data in GPU C++ function..." << std::endl;
    std::cout << "State root: " << uint256_to_hex(state->root) << std::endl;
    std::cout << "Number of accounts: " << state->accounts.size() << std::endl;
    
    try {
        int count = 0;
        for (const auto& account : state->accounts) {
            if (count >= 10) {
                std::cout << "\n... and " << state->accounts.size() - 10 << " more accounts" << std::endl;
                break;
            }
            
            std::cout << "\n=== Account " << uint256_to_hex(account.address) << " ===" << std::endl;
            std::cout << "  Balance:  " << uint256_to_hex(account.balance) << std::endl;
            std::cout << "  Nonce:    " << account.nonce << std::endl;
            std::cout << "  Has Code: " << (account.hasCode ? "true" : "false") << std::endl;
            
            // Print root
            if (!account.root.empty()) {
                std::cout << "  Root:     " << bytes_to_hex(account.root.data(), account.root.size()) << std::endl;
            }
            
            // Print code hash
            if (!account.codeHash.empty()) {
                std::cout << "  CodeHash: " << bytes_to_hex(account.codeHash.data(), account.codeHash.size()) << std::endl;
            }
            
            // Print code information
            if (!account.code.empty()) {
                std::cout << "  Code:     " << bytes_to_hex(account.code.data(), std::min(64, (int)account.code.size())) << "..." << std::endl;
                std::cout << "  Code Length: " << account.code.size() << " bytes" << std::endl;
            } else {
                std::cout << "  Code:     <empty>" << std::endl;
            }
            
            // Print storage
            if (!account.storageKeys.empty()) {
                std::cout << "  Storage:" << std::endl;
                for (size_t i = 0; i < std::min(size_t(5), account.storageKeys.size()); i++) {
                    std::cout << "    " << uint256_to_hex(account.storageKeys[i]) << ": " 
                              << uint256_to_hex(account.storageVals[i]) << std::endl;
                }
                if (account.storageKeys.size() > 5) {
                    std::cout << "    ... and " << account.storageKeys.size() - 5 << " more entries" << std::endl;
                }
            } else {
                std::cout << "  Storage:  <empty>" << std::endl;
            }
            
            count++;
        }
        
        // GPU processing would happen here
        // For example, could launch a CUDA kernel:
        // launchGPUKernel<<<blocks, threads>>>(state->accounts);
        
        return 0; // Success
    } catch (const std::exception& e) {
        std::cerr << "Error in process_state_data_gpu: " << e.what() << std::endl;
        return 1; // Error code
    } catch (...) {
        std::cerr << "Unknown error in process_state_data_gpu" << std::endl;
        return 2; // Different error code
    }
}

// Free memory
void free_state_data(StateDataGPU* state) {
    delete state;
}