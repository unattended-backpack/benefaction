// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ERC20ReturnFalseMock} from 'test/utils/ERC20ReturnFalseMock.sol';

contract MockToken is ERC20ReturnFalseMock {
    constructor() {}

    function mint(address account, uint256 amount) external {
        _mint(account, amount);
    }
}
