// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract Test{
    uint256 public counter1 = 0;
    uint256 public counter2 = 42;

    function set1(uint input) public {
        if (input % 100 == 69)
            counter1 ++;
    }

    function bug1() public {
        assert(counter1 == 0); // assertion
        counter1 = 0;
    }

    function bug2(uint input) public {
            counter2 = counter2*input; // overflow
    }
}

