pragma solidity ^0.7.0;
contract Test {

    // uint256 public counter = 2 ** 256/4;
    uint256 public counter = 1;
    uint256 public counter2 = 32;
    uint256 public counter3 = 3;
    function inc(uint256 val) public returns (uint256) {
        // uint256 tmp = counter;
        if (val % 2 == 0) {
            counter += 1;
        }

        if (val % 8 == 1) {
            counter2 *= 2;
        }
        // assert(tmp <= counter);
        // assert(counter <3);
        // return (counter - tmp);
    }
    function bug() public {
        assert (counter < 3);
    }

    function bug2() public {
        assert (counter2 <=123);
    }
}