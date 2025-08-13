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


contract AttackerReentrancy{
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
    function onERC1155Received(address, address, uint256, uint256, bytes memory) public virtual returns (bytes4) {
        fallback_logic();
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] memory, uint256[] memory, bytes memory) public virtual returns (bytes4) {
        fallback_logic();
        return this.onERC1155BatchReceived.selector;
    }

    function onERC721Received(address, address, uint256, bytes memory) public virtual returns (bytes4) {
        fallback_logic();
        return this.onERC721Received.selector;
    }

}