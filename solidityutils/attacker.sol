// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract TokenReceiver{
    function onERC1155Received(address, address, uint256, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] memory, uint256[] memory, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    function onERC721Received(address, address, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC721Received.selector;
    }
    // can add more popular receivers here

}

contract AttackerTransparent is TokenReceiver{
    // fallback() payable external{}
    fallback(bytes calldata) payable external returns(bytes memory res){
        res = new bytes(128);
        // by pass the check for return value of bool type
        res[31] = 0x01; // heuristically return true as bool
        return res;
        // res = new bytes(1024);
        // by pass the check for return value of bool type
        // res[31] = 0x01; // heuristically return true as bool
        // return res;
    }
}


// this constract to set to all blank addresses.
contract AttackerTransparentEnhanced is TokenReceiver{
    address[8] public addresses; // configurable
    uint256[16] public numbers; // configurable
    // dont need constructor, just bypass genesis and add storage
    // constructor(address[8] _addresses, uint256[16]  _numbers){
    //     for (uint8 i = 0; i < 8; i++){
    //         addresses[i] = _addresses[i]; 
    //     }
    //     for (uint8 i = 0; i < 16; i++){
    //         numbers[i] = _numbers[i]; 
    //     }
    // }
    // fallback() payable external{}
    fallback(bytes calldata) payable external returns(bytes memory res){
        res = new bytes(128); 
        uint256 mode = block.number % 3;
        uint256 word = 0;
        if (mode == 0) {
            word = 1;
            // bool false: word remains 0
        } else if (mode == 1) {
            // address: cast to uint160 for right-alignment
            word = uint160(addresses[block.timestamp % 8]);
        } else {
            // number: direct uint256 value
            uint32 seed = uint32(block.timestamp);
            if (seed % 2 == 0){
                seed = seed * 1664525 +	1013904223; // uint32
                word = seed;

                seed = seed * 1664525 +	1013904223; // uint32
                if (seed % 2 == 0){ // another word
                    word = word << 32;
                    word = word | seed;
                } 
            } else {
                // get from constant list 
                seed = (seed * 1664525 + 1013904223) % 16;
                word = numbers[seed];
            }
            
        }
        
        // Use assembly to copy the word to the first 32 bytes of res's data
        assembly {
            mstore(add(res, 32), word) // Stores word right-aligned in the first slot
        }
        return res;
        // res = new bytes(1024);
        // by pass the check for return value of bool type
        // res[31] = 0x01; // heuristically return true as bool
        // return res;
    }
}

contract AttackerReentrancy is TokenReceiver{
    uint public count; // slot 0
    function fallback_logic() internal {
        // for simplicity, we reset the state every tx inside CuEVM fuzzing feature
        count = count + 1;
        if (count < 2){
            address(msg.sender).call{value: 0}("");
        } 
        
    }
   
    fallback(bytes calldata) payable external returns(bytes memory res){
        // require(msg.data.length == 0 || msg.data.length == 32); //Reject other function calls not send & call
        fallback_logic();
        res = new bytes(128);
        // by pass the check for return value of bool type
        res[31] = 0x01; // heuristically return true as bool
        return res;
        // TODO revert this logic to return conforming data to the caller
        // res = new bytes(1024);
        // // by pass the check for return value of bool type
        // res[31] = 0x01; // heuristically return true as bool
        // return res;
    }

    function balanceOf(address) public view returns(uint){
        return 1000000000000;
    }

}