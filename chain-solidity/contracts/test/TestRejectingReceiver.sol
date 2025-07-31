// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

contract TestRejectingReceiver {
    receive() external payable {
        require(false, "No!");
    }
}
