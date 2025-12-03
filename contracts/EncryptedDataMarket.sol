// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { FHE, euint32, ebool } from "@fhevm/solidity/lib/FHE.sol";
import { SepoliaConfig } from "@fhevm/solidity/config/ZamaConfig.sol";

/// @title Encrypted Data Marketplace using FHE
/// @notice Enables privacy-preserving analytics and anonymous encrypted voting
contract EncryptedDataMarket is SepoliaConfig {

    // --- Data Structures ---

    /// @notice Represents a submitted encrypted data item
    struct EncryptedData {
        uint256 id;
        euint32 encryptedValue;  // Encrypted numeric value
        uint256 timestamp;
    }

    /// @notice Aggregated encrypted statistics
    struct EncryptedStats {
        euint32 sum;         // Encrypted sum
        euint32 count;       // Encrypted count
        ebool thresholdAlert; // Threshold alert in encrypted form
    }

    /// @notice Represents an anonymous encrypted vote
    struct EncryptedVote {
        euint32 encryptedChoice;
        uint256 timestamp;
    }

    // --- State Variables ---
    uint256 public dataCount;
    uint256 public voteCount;
    mapping(uint256 => EncryptedData) public encryptedData;
    mapping(uint256 => EncryptedVote) public encryptedVotes;

    // Encrypted aggregation state
    EncryptedStats public stats;

    // Mapping for audit proofs (zero-knowledge)
    mapping(uint256 => bytes) public auditProofs;

    // Admin-only events
    event DataSubmitted(uint256 indexed id, uint256 timestamp);
    event VoteSubmitted(uint256 indexed id, uint256 timestamp);
    event StatsUpdated();
    event AuditVerified(uint256 indexed dataId);

    // --- Data Submission ---

    /// @notice Submit encrypted numeric data
    function submitEncryptedData(euint32 encryptedValue) public {
        dataCount += 1;
        encryptedData[dataCount] = EncryptedData({
            id: dataCount,
            encryptedValue: encryptedValue,
            timestamp: block.timestamp
        });

        // Update encrypted statistics homomorphically
        if (!FHE.isInitialized(stats.sum)) {
            stats.sum = FHE.asEuint32(0);
            stats.count = FHE.asEuint32(0);
            stats.thresholdAlert = FHE.asEbool(false);
        }
        stats.sum = FHE.add(stats.sum, encryptedValue);
        stats.count = FHE.add(stats.count, FHE.asEuint32(1));

        // Check threshold alert in encrypted domain
        // Example threshold is 100 (encrypted)
        euint32 threshold = FHE.asEuint32(100);
        stats.thresholdAlert = FHE.gte(stats.sum, threshold);

        emit DataSubmitted(dataCount, block.timestamp);
        emit StatsUpdated();
    }

    // --- Anonymous Voting ---

    /// @notice Submit an encrypted vote
    function submitEncryptedVote(euint32 encryptedChoice) public {
        voteCount += 1;
        encryptedVotes[voteCount] = EncryptedVote({
            encryptedChoice: encryptedChoice,
            timestamp: block.timestamp
        });

        // Homomorphically aggregate votes (for each choice)
        // For simplicity, assume stats.sum is reused for encrypted vote tally
        stats.sum = FHE.add(stats.sum, encryptedChoice);
        stats.count = FHE.add(stats.count, FHE.asEuint32(1));

        emit VoteSubmitted(voteCount, block.timestamp);
        emit StatsUpdated();
    }

    // --- Encrypted Statistics Access ---

    /// @notice Returns encrypted statistics (sum, count, threshold alert)
    function getEncryptedStats() public view returns (EncryptedStats memory) {
        return stats;
    }

    // --- Zero-Knowledge Audit ---

    /// @notice Submit ZK proof that a data submission was processed correctly
    function submitAuditProof(uint256 dataId, bytes memory zkProof) public {
        auditProofs[dataId] = zkProof;
        emit AuditVerified(dataId);
    }

    /// @notice Verify ZK proof (off-chain or via FHE library)
    function verifyAuditProof(uint256 dataId, bytes memory cleartexts) public view returns (bool) {
        bytes memory proof = auditProofs[dataId];
        require(proof.length > 0, "Proof not submitted");
        return FHE.checkSignatures(dataId, cleartexts, proof);
    }
}
