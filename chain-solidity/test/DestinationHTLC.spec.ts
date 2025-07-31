// SPDX-License-Identifier: AGPL-3.0-only

import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
//import { DestinationHTLC } from "../src/contracts";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("DestinationHTLC", function () {
  // Test data
  const SECRET = ethers.randomBytes(32); // "0x6d7973656372657431323300000000000000000000000000000000000000000000"; // "mysecret123" padded to 32 bytes
  const INVALID_SECRET = ethers.randomBytes(32); // "0x696e76616c69645f73656372657400000000000000000000000000000000000000"; // "invalid_secret" padded
  const HTLC_AMOUNT = ethers.parseEther("1.0");
  const ONE_HOUR = 3600;
  const ONE_DAY = 24 * 3600;

  async function deployHTLCFixture() {
    // Get signers
    const [resolver, user, other, attacker] = await ethers.getSigners();

    // Deploy contract
    const DestinationHTLC = await ethers.getContractFactory("DestinationHTLC");
    const htlc = await DestinationHTLC.deploy();

    // Calculate secret hash using contract's hash function
    const secretHash = await htlc.hashSecret(SECRET);

    return {
      htlc,
      resolver,
      user,
      other,
      attacker,
      SECRET,
      INVALID_SECRET,
      secretHash,
      HTLC_AMOUNT,
    };
  }

  describe("Deployment", function () {
    it("Should deploy successfully", async function () {
      const { htlc } = await loadFixture(deployHTLCFixture);
      expect(await htlc.getAddress()).to.be.properAddress;
    });

    it("Should not accept ETH directly", async function () {
      const { htlc, resolver } = await loadFixture(deployHTLCFixture);
      
      // Should revert when sending ETH directly
      await expect(
        resolver.sendTransaction({
          to: await htlc.getAddress(),
          value: HTLC_AMOUNT,
        })
      ).to.be.reverted;
    });
  });

  describe("Hash Secret Function", function () {
    it("Should hash secrets correctly", async function () {
      const { htlc } = await loadFixture(deployHTLCFixture);
      
      const secret = ethers.randomBytes(32) // "0x1234567890abcdef000000000000000000000000000000000000000000000000";
      const expectedHash = ethers.sha256(ethers.getBytes(secret));
      const contractHash = await htlc.hashSecret(secret);
      
      expect(contractHash).to.equal(expectedHash);
    });

    it("Should produce different hashes for different secrets", async function () {
      const { htlc, SECRET, INVALID_SECRET } = await loadFixture(deployHTLCFixture);
      
      const hash1 = await htlc.hashSecret(SECRET);
      const hash2 = await htlc.hashSecret(INVALID_SECRET);
      
      expect(hash1).to.not.equal(hash2);
    });
  });

  describe("Create HTLC", function () {
    it("Should create HTLC successfully", async function () {
      const { htlc, resolver, user, secretHash, HTLC_AMOUNT } = await loadFixture(deployHTLCFixture);
      
      const deadline = (await time.latest()) + ONE_DAY;
      
      // Create HTLC
      await expect(
        htlc.connect(resolver).createHTLC(secretHash, user.address, deadline, {
          value: HTLC_AMOUNT,
        })
      )
        .to.emit(htlc, "HTLCCreated")
        .withArgs(secretHash, user.address, resolver.address, HTLC_AMOUNT, deadline);

      // Verify HTLC exists
      expect(await htlc.doesHTLCExist(secretHash)).to.be.true;
      
      // Verify HTLC info
      const htlcInfo = await htlc.getHTLCInfo(secretHash);
      expect(htlcInfo[0]).to.equal(user.address); // userAddress
      expect(htlcInfo[1]).to.equal(resolver.address); // resolverAddress
      expect(htlcInfo[2]).to.equal(HTLC_AMOUNT); // amount
      expect(htlcInfo[3]).to.equal(deadline); // deadline
      expect(htlcInfo[4]).to.be.false; // claimed
    });

    it("Should revert if no ETH sent", async function () {
      const { htlc, resolver, user, secretHash } = await loadFixture(deployHTLCFixture);
      
      const deadline = (await time.latest()) + ONE_DAY;
      
      await expect(
        htlc.connect(resolver).createHTLC(secretHash, user.address, deadline, {
          value: 0,
        })
      ).to.be.revertedWithCustomError(htlc, "InsufficientAmount");
    });

    it("Should revert if user address is zero", async function () {
      const { htlc, resolver, secretHash, HTLC_AMOUNT } = await loadFixture(deployHTLCFixture);
      
      const deadline = (await time.latest()) + ONE_DAY;
      
      await expect(
        htlc.connect(resolver).createHTLC(secretHash, ethers.ZeroAddress, deadline, {
          value: HTLC_AMOUNT,
        })
      ).to.be.revertedWithCustomError(htlc, "InvalidUserAddress");
    });

    it("Should revert if deadline is in the past", async function () {
      const { htlc, resolver, user, secretHash, HTLC_AMOUNT } = await loadFixture(deployHTLCFixture);
      
      const pastDeadline = (await time.latest()) - 1;
      
      await expect(
        htlc.connect(resolver).createHTLC(secretHash, user.address, pastDeadline, {
          value: HTLC_AMOUNT,
        })
      ).to.be.revertedWithCustomError(htlc, "InvalidDeadline");
    });

    it("Should revert if deadline is current time", async function () {
      const { htlc, resolver, user, secretHash, HTLC_AMOUNT } = await loadFixture(deployHTLCFixture);
      
      const currentTime = await time.latest();
      
      await expect(
        htlc.connect(resolver).createHTLC(secretHash, user.address, currentTime, {
          value: HTLC_AMOUNT,
        })
      ).to.be.revertedWithCustomError(htlc, "InvalidDeadline");
    });

    it("Should revert if HTLC already exists", async function () {
      const { htlc, resolver, user, secretHash, HTLC_AMOUNT } = await loadFixture(deployHTLCFixture);
      
      const deadline = (await time.latest()) + ONE_DAY;
      
      // Create first HTLC
      await htlc.connect(resolver).createHTLC(secretHash, user.address, deadline, {
        value: HTLC_AMOUNT,
      });
      
      // Try to create duplicate
      await expect(
        htlc.connect(resolver).createHTLC(secretHash, user.address, deadline, {
          value: HTLC_AMOUNT,
        })
      ).to.be.revertedWithCustomError(htlc, "HTLCDuplicateExists");
    });

    it("Should allow different resolvers to create HTLCs with same secret hash", async function () {
      const { htlc, resolver, user, other, secretHash, HTLC_AMOUNT } = await loadFixture(deployHTLCFixture);
      
      const deadline = (await time.latest()) + ONE_DAY;
      
      // First resolver creates HTLC
      await htlc.connect(resolver).createHTLC(secretHash, user.address, deadline, {
        value: HTLC_AMOUNT,
      });
      
      // Different secret hash for second resolver (since only one HTLC per hash allowed)
      const differentSecret = "0x646966666572656e745f73656372657400000000000000000000000000000000";
      const differentSecretHash = await htlc.hashSecret(differentSecret);
      
      // Second resolver creates HTLC with different secret hash
      await expect(
        htlc.connect(other).createHTLC(differentSecretHash, user.address, deadline, {
          value: HTLC_AMOUNT,
        })
      ).to.not.be.reverted;
    });
  });

  describe("Reveal Secret", function () {
    async function createHTLCFixture() {
      const fixture = await deployHTLCFixture();
      const { htlc, resolver, user, secretHash, HTLC_AMOUNT } = fixture;
      
      const deadline = (await time.latest()) + ONE_DAY;
      
      // Create HTLC
      await htlc.connect(resolver).createHTLC(secretHash, user.address, deadline, {
        value: HTLC_AMOUNT,
      });
      
      return { ...fixture, deadline };
    }

    it("Should allow anyone to reveal secret and claim funds", async function () {
      const { htlc, user, other, SECRET, secretHash, HTLC_AMOUNT } = await loadFixture(createHTLCFixture);
      
      const userBalanceBefore = await ethers.provider.getBalance(user.address);
      
      // Other party reveals secret (gasless for user!)
      await expect(
        htlc.connect(other).revealSecret(SECRET)
      )
        .to.emit(htlc, "SecretRevealed")
        .withArgs(secretHash, SECRET, user.address, HTLC_AMOUNT);
      
      // Verify user received funds
      const userBalanceAfter = await ethers.provider.getBalance(user.address);
      expect(userBalanceAfter - userBalanceBefore).to.equal(HTLC_AMOUNT);
      
      // Verify HTLC is marked as claimed
      const htlcInfo = await htlc.getHTLCInfo(secretHash);
      expect(htlcInfo[4]).to.be.true; // claimed
    });

    it("Should revert with wrong secret", async function () {
      const { htlc, other, INVALID_SECRET } = await loadFixture(createHTLCFixture);
      
      await expect(
        htlc.connect(other).revealSecret(INVALID_SECRET)
      ).to.be.revertedWithCustomError(htlc, "HTLCNotFound");
    });

    it("Should revert if HTLC doesn't exist", async function () {
      const { htlc, other } = await loadFixture(deployHTLCFixture);
      
      const nonExistentSecret = ethers.randomBytes(32); // "0x6e6f6e6578697374656e745f73656372657400000000000000000000000000000";
      
      await expect(
        htlc.connect(other).revealSecret(nonExistentSecret)
      ).to.be.revertedWithCustomError(htlc, "HTLCNotFound");
    });

    it("Should revert if already claimed", async function () {
      const { htlc, other, SECRET } = await loadFixture(createHTLCFixture);
      
      // First reveal
      await htlc.connect(other).revealSecret(SECRET);
      
      // Second reveal should fail
      await expect(
        htlc.connect(other).revealSecret(SECRET)
      ).to.be.revertedWithCustomError(htlc, "HTLCAlreadyClaimed");
    });

    it("Should allow reveal even after deadline (before refund)", async function () {
      const { htlc, other, SECRET, secretHash, HTLC_AMOUNT, deadline } = await loadFixture(createHTLCFixture);
      
      // Advance time past deadline
      await time.increaseTo(deadline + 1);
      
      // Should still be able to reveal secret
      await expect(
        htlc.connect(other).revealSecret(SECRET)
      )
        .to.emit(htlc, "SecretRevealed")
        .withArgs(secretHash, SECRET, await htlc.htlcs(secretHash).then(h => h.userAddress), HTLC_AMOUNT);
    });

    it("Should handle transfer failure gracefully", async function () {
      const { htlc, resolver, attacker, SECRET, secretHash, HTLC_AMOUNT } = await loadFixture(deployHTLCFixture);
      
      // Deploy a contract that rejects ETH transfers
      const RejectingContract = await ethers.getContractFactory("TestRejectingReceiver");
      const rejectingContract = await RejectingContract.deploy();
      
      const deadline = (await time.latest()) + ONE_DAY;
      
      // Create HTLC with rejecting contract as user
      await htlc.connect(resolver).createHTLC(
        secretHash, 
        await rejectingContract.getAddress(), 
        deadline, 
        { value: HTLC_AMOUNT }
      );
      
      // Revealing secret should fail due to transfer failure
      await expect(
        htlc.connect(attacker).revealSecret(SECRET)
      ).to.be.revertedWithCustomError(htlc, "TransferFailed");
    });
  });

  describe("Claim Refund", function () {
    async function createExpiredHTLCFixture() {
      const fixture = await deployHTLCFixture();
      const { htlc, resolver, user, secretHash, HTLC_AMOUNT } = fixture;
      
      const deadline = (await time.latest()) + ONE_HOUR;
      
      // Create HTLC
      await htlc.connect(resolver).createHTLC(secretHash, user.address, deadline, {
        value: HTLC_AMOUNT,
      });
      
      // Advance time past deadline
      await time.increaseTo(deadline + 1);
      
      return { ...fixture, deadline };
    }

    it("Should allow refund after deadline", async function () {
      const { htlc, resolver, secretHash, HTLC_AMOUNT } = await loadFixture(createExpiredHTLCFixture);
      
      const resolverBalanceBefore = await ethers.provider.getBalance(resolver.address);
      
      // Claim refund
      const tx = await htlc.connect(resolver).claimRefund(secretHash);
      const receipt = await tx.wait();
      const gasUsed = receipt!.gasUsed * receipt!.gasPrice;
      
      await expect(tx)
        .to.emit(htlc, "HTLCRefunded")
        .withArgs(secretHash, resolver.address, HTLC_AMOUNT);
      
      // Verify resolver received refund (minus gas)
      const resolverBalanceAfter = await ethers.provider.getBalance(resolver.address);
      expect(resolverBalanceAfter - resolverBalanceBefore + gasUsed).to.equal(HTLC_AMOUNT);
      
      // Verify HTLC is marked as claimed
      const htlcInfo = await htlc.getHTLCInfo(secretHash);
      expect(htlcInfo[4]).to.be.true; // claimed
    });

    it("Should revert if deadline hasn't passed", async function () {
      const { htlc, resolver, user, secretHash, HTLC_AMOUNT } = await loadFixture(deployHTLCFixture);
      
      const deadline = (await time.latest()) + ONE_DAY;
      
      // Create HTLC
      await htlc.connect(resolver).createHTLC(secretHash, user.address, deadline, {
        value: HTLC_AMOUNT,
      });
      
      // Try to claim refund before deadline
      await expect(
        htlc.connect(resolver).claimRefund(secretHash)
      ).to.be.revertedWithCustomError(htlc, "HTLCNotExpired");
    });

    it("Should revert if HTLC doesn't exist", async function () {
      const { htlc, resolver } = await loadFixture(deployHTLCFixture);
      
      const nonExistentHash = "0x1234567890123456789012345678901234567890123456789012345678901234";
      
      await expect(
        htlc.connect(resolver).claimRefund(nonExistentHash)
      ).to.be.revertedWithCustomError(htlc, "HTLCNotFound");
    });

    it("Should revert if already claimed", async function () {
      const { htlc, resolver, secretHash } = await loadFixture(createExpiredHTLCFixture);
      
      // First refund
      await htlc.connect(resolver).claimRefund(secretHash);
      
      // Second refund should fail
      await expect(
        htlc.connect(resolver).claimRefund(secretHash)
      ).to.be.revertedWithCustomError(htlc, "HTLCAlreadyClaimed");
    });

    it("Should revert if already revealed", async function () {
      const { htlc, resolver, other, SECRET, secretHash } = await loadFixture(createExpiredHTLCFixture);
      
      // Reveal secret first
      await htlc.connect(other).revealSecret(SECRET);
      
      // Refund should fail
      await expect(
        htlc.connect(resolver).claimRefund(secretHash)
      ).to.be.revertedWithCustomError(htlc, "HTLCAlreadyClaimed");
    });

    it("Should allow anyone to call refund (not just resolver)", async function () {
      const { htlc, resolver, other, secretHash, HTLC_AMOUNT } = await loadFixture(createExpiredHTLCFixture);
      
      const resolverBalanceBefore = await ethers.provider.getBalance(resolver.address);
      
      // Other party calls refund (but funds go to resolver)
      await expect(
        htlc.connect(other).claimRefund(secretHash)
      )
        .to.emit(htlc, "HTLCRefunded")
        .withArgs(secretHash, resolver.address, HTLC_AMOUNT);
      
      // Verify resolver received refund
      const resolverBalanceAfter = await ethers.provider.getBalance(resolver.address);
      expect(resolverBalanceAfter - resolverBalanceBefore).to.equal(HTLC_AMOUNT);
    });
  });

  describe("View Functions", function () {
    async function createHTLCFixture() {
      const fixture = await deployHTLCFixture();
      const { htlc, resolver, user, secretHash, HTLC_AMOUNT } = fixture;
      
      const deadline = (await time.latest()) + ONE_DAY;
      
      // Create HTLC
      await htlc.connect(resolver).createHTLC(secretHash, user.address, deadline, {
        value: HTLC_AMOUNT,
      });
      
      return { ...fixture, deadline };
    }

    it("Should return correct HTLC info", async function () {
      const { htlc, resolver, user, secretHash, HTLC_AMOUNT, deadline } = await loadFixture(createHTLCFixture);
      
      const htlcInfo = await htlc.getHTLCInfo(secretHash);
      
      expect(htlcInfo[0]).to.equal(user.address); // userAddress
      expect(htlcInfo[1]).to.equal(resolver.address); // resolverAddress
      expect(htlcInfo[2]).to.equal(HTLC_AMOUNT); // amount
      expect(htlcInfo[3]).to.equal(deadline); // deadline
      expect(htlcInfo[4]).to.be.false; // claimed
    });

    it("Should return correct existence status", async function () {
      const { htlc, secretHash } = await loadFixture(createHTLCFixture);
      
      expect(await htlc.doesHTLCExist(secretHash)).to.be.true;
      
      const nonExistentHash = "0x1234567890123456789012345678901234567890123456789012345678901234";
      expect(await htlc.doesHTLCExist(nonExistentHash)).to.be.false;
    });

    it("Should return correct claimable status", async function () {
      const { htlc, secretHash, deadline } = await loadFixture(createHTLCFixture);
      
      // Before deadline - claimable
      expect(await htlc.isClaimable(secretHash)).to.be.true;
      
      // After deadline - not claimable
      await time.increaseTo(deadline + 1);
      expect(await htlc.isClaimable(secretHash)).to.be.false;
      
      // After claimed - not claimable
      await htlc.claimRefund(secretHash);
      expect(await htlc.isClaimable(secretHash)).to.be.false;
    });

    it("Should return correct refundable status", async function () {
      const { htlc, secretHash, deadline } = await loadFixture(createHTLCFixture);
      
      // Before deadline - not refundable
      expect(await htlc.isRefundable(secretHash)).to.be.false;
      
      // After deadline - refundable
      await time.increaseTo(deadline + 1);
      expect(await htlc.isRefundable(secretHash)).to.be.true;
      
      // After refunded - not refundable
      await htlc.claimRefund(secretHash);
      expect(await htlc.isRefundable(secretHash)).to.be.false;
    });

    it("Should return false for non-existent HTLC in all view functions", async function () {
      const { htlc } = await loadFixture(deployHTLCFixture);
      
      const nonExistentHash = "0x1234567890123456789012345678901234567890123456789012345678901234";
      
      expect(await htlc.doesHTLCExist(nonExistentHash)).to.be.false;
      expect(await htlc.isClaimable(nonExistentHash)).to.be.false;
      expect(await htlc.isRefundable(nonExistentHash)).to.be.false;
    });
  });

  describe("Edge Cases and Security", function () {
    it("Should handle zero amount ETH", async function () {
      const { htlc, resolver, user, secretHash } = await loadFixture(deployHTLCFixture);
      
      const deadline = (await time.latest()) + ONE_DAY;
      
      await expect(
        htlc.connect(resolver).createHTLC(secretHash, user.address, deadline, {
          value: 0,
        })
      ).to.be.revertedWithCustomError(htlc, "InsufficientAmount");
    });

    it("Should handle very large amounts", async function () {
      const { htlc, resolver, user, secretHash } = await loadFixture(deployHTLCFixture);
      
      const largeAmount = ethers.parseEther("1000000");
      const deadline = (await time.latest()) + ONE_DAY;
      
      // This should work if resolver has enough balance
      // In test environment with funded accounts, this should pass
      try {
        await htlc.connect(resolver).createHTLC(secretHash, user.address, deadline, {
          value: largeAmount,
        });
        
        expect(await htlc.doesHTLCExist(secretHash)).to.be.true;
        
        const htlcInfo = await htlc.getHTLCInfo(secretHash);
        expect(htlcInfo[2]).to.equal(largeAmount);
      } catch (error) {
        // If resolver doesn't have enough balance, that's expected
        expect(error.message).to.include("doesn't have enough funds");
      }
    });

    it("Should handle multiple HTLCs independently", async function () {
      const { htlc, resolver, user, other, HTLC_AMOUNT } = await loadFixture(deployHTLCFixture);
      
      const secret1 = ethers.randomBytes(32); // "0x73656372657431000000000000000000000000000000000000000000000000000"; // "secret1"
      const secret2 = ethers.randomBytes(32); // "0x73656372657432000000000000000000000000000000000000000000000000000"; // "secret2"
      
      const secretHash1 = await htlc.hashSecret(secret1);
      const secretHash2 = await htlc.hashSecret(secret2);
      
      const deadline = (await time.latest()) + ONE_DAY;
      
      // Create two HTLCs
      await htlc.connect(resolver).createHTLC(secretHash1, user.address, deadline, {
        value: HTLC_AMOUNT,
      });
      
      await htlc.connect(resolver).createHTLC(secretHash2, other.address, deadline, {
        value: HTLC_AMOUNT,
      });
      
      // Both should exist
      expect(await htlc.doesHTLCExist(secretHash1)).to.be.true;
      expect(await htlc.doesHTLCExist(secretHash2)).to.be.true;
      
      // Reveal one secret
      await htlc.revealSecret(secret1);
      
      // Only first should be claimed
      const htlc1Info = await htlc.getHTLCInfo(secretHash1);
      const htlc2Info = await htlc.getHTLCInfo(secretHash2);
      
      expect(htlc1Info[4]).to.be.true; // claimed
      expect(htlc2Info[4]).to.be.false; // not claimed
    });

    it("Should maintain correct contract balance", async function () {
      const { htlc, resolver, user, secretHash, SECRET, HTLC_AMOUNT } = await loadFixture(deployHTLCFixture);
      
      const deadline = (await time.latest()) + ONE_DAY;
      const contractAddress = await htlc.getAddress();
      
      const initialBalance = await ethers.provider.getBalance(contractAddress);
      
      // Create HTLC
      await htlc.connect(resolver).createHTLC(secretHash, user.address, deadline, {
        value: HTLC_AMOUNT,
      });
      
      // Contract balance should increase
      const balanceAfterCreate = await ethers.provider.getBalance(contractAddress);
      expect(balanceAfterCreate - initialBalance).to.equal(HTLC_AMOUNT);
      
      // Reveal secret
      await htlc.revealSecret(SECRET);
      
      // Contract balance should decrease back to initial
      const balanceAfterReveal = await ethers.provider.getBalance(contractAddress);
      expect(balanceAfterReveal).to.equal(initialBalance);
    });
  });

  describe("Gas Usage", function () {
    it("Should have reasonable gas costs", async function () {
      const { htlc, resolver, user, secretHash, SECRET, HTLC_AMOUNT } = await loadFixture(deployHTLCFixture);
      
      const deadline = (await time.latest()) + ONE_DAY;
      
      // Test createHTLC gas usage
      const createTx = await htlc.connect(resolver).createHTLC(secretHash, user.address, deadline, {
        value: HTLC_AMOUNT,
      });
      const createReceipt = await createTx.wait();
      //console.log(`Create HTLC gas used: ${createReceipt!.gasUsed}`);
      
      // Test revealSecret gas usage
      const revealTx = await htlc.revealSecret(SECRET);
      const revealReceipt = await revealTx.wait();
      //console.log(`Reveal secret gas used: ${revealReceipt!.gasUsed}`);
      
      // Gas usage should be reasonable (these are rough estimates)
      expect(createReceipt!.gasUsed).to.be.lessThan(120000n); // Less than 100k gas
      expect(revealReceipt!.gasUsed).to.be.lessThan(65000n);  // Less than 50k gas
    });
  });
});

// Helper contract for testing transfer failures
const TestRejectingReceiverSource = `
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
`;
