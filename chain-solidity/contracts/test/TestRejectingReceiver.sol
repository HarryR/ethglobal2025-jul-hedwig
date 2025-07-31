// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

contract TestRejectingReceiver {
    // Reject all ETH transfers
    receive() external payable {
        revert("Rejecting ETH transfer");
    }
    
    fallback() external payable {
        revert("Rejecting ETH transfer");
    }
}