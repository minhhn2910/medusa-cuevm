#include "state_gpu.h"
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <sstream>
#include <iomanip>

// Account data structure
struct Account {
    std::string address;
    std::string balance;
    unsigned long nonce;
    std::vector<unsigned char> root;
    std::vector<unsigned char> codeHash;
    std::vector<unsigned char> code;
    std::vector<std::string> storageKeys;
    std::vector<std::string> storageVals;
};

// State data container
struct StateDataGPU {
    std::string root;
    std::vector<Account> accounts;
};

// Helper function to convert bytes to hex string
std::string bytes_to_hex(const unsigned char* data, int len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < len; i++) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

// Create a new state data container
StateDataGPU* create_state_data() {
    return new StateDataGPU();
}

// Add an account to state data
void add_account(StateDataGPU* state, 
                 const char* address, 
                 const char* balance, 
                 unsigned long nonce,
                 const unsigned char* root, int root_len,
                 const unsigned char* code_hash, int code_hash_len,
                 const unsigned char* code, int code_len) {
    
    Account account;
    account.address = address;
    account.balance = balance;
    account.nonce = nonce;
    
    // Copy root
    if (root && root_len > 0) {
        account.root.assign(root, root + root_len);
    }
    
    // Copy code hash
    if (code_hash && code_hash_len > 0) {
        account.codeHash.assign(code_hash, code_hash + code_hash_len);
    }
    
    // Copy code
    if (code && code_len > 0) {
        account.code.assign(code, code + code_len);
    }
    
    state->accounts.push_back(account);
}

// Add a storage entry to the most recently added account
void add_storage_entry(StateDataGPU* state, const char* key, const char* value) {
    if (!state->accounts.empty()) {
        state->accounts.back().storageKeys.push_back(key);
        state->accounts.back().storageVals.push_back(value);
    }
}

// Set state root
void set_state_root(StateDataGPU* state, const char* root) {
    state->root = root;
}

// Process state data on GPU
void process_state_data_gpu(StateDataGPU* state) {
    std::cout << "Processing state data in GPU C++ function..." << std::endl;
    std::cout << "State root: " << state->root << std::endl;
    std::cout << "Number of accounts: " << state->accounts.size() << std::endl;
    
    int count = 0;
    for (const auto& account : state->accounts) {
        if (count >= 10) {
            std::cout << "\n... and " << state->accounts.size() - 10 << " more accounts" << std::endl;
            break;
        }
        
        std::cout << "\n=== Account " << account.address << " ===" << std::endl;
        std::cout << "  Balance:  " << account.balance << std::endl;
        std::cout << "  Nonce:    " << account.nonce << std::endl;
        
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
            std::cout << "  Code:     " << bytes_to_hex(account.code.data(), account.code.size()) << std::endl;
            std::cout << "  Code Length: " << account.code.size() << " bytes" << std::endl;
        } else {
            std::cout << "  Code:     <empty>" << std::endl;
        }
        
        // Print storage
        if (!account.storageKeys.empty()) {
            std::cout << "  Storage:" << std::endl;
            for (size_t i = 0; i < account.storageKeys.size(); i++) {
                std::cout << "    " << account.storageKeys[i] << ": " << account.storageVals[i] << std::endl;
            }
        } else {
            std::cout << "  Storage:  <empty>" << std::endl;
        }
        
        count++;
    }
    
    // GPU processing would happen here
    // ...
}

// Free memory
void free_state_data(StateDataGPU* state) {
    delete state;
}