// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title DemoCommerce — minimal ERC-8183 event emitter for Agent Passport demo flows.
/// @notice Emits the exact event signatures the indexer parses from the production
///         AgenticCommerceUpgradeable contract, so the full event->stats pipeline
///         runs against authentic shapes.
contract DemoCommerce {
    uint256 public nextJobId = 1;

    event JobCreated(uint256 indexed jobId, address indexed client, address indexed provider, address evaluator, uint256 expiredAt, address hook);
    event JobFunded(uint256 indexed jobId, address indexed client, address indexed provider, uint256 amount);
    event JobSubmitted(uint256 indexed jobId, address indexed provider, bytes32 deliverable);
    event JobCompleted(uint256 indexed jobId, address indexed evaluator, bytes32 reason);
    event JobRejected(uint256 indexed jobId, address indexed rejector, bytes32 reason);
    event JobExpired(uint256 indexed jobId);
    event PaymentReleased(uint256 indexed jobId, address indexed provider, uint256 amount);

    /// @notice outcome: 0 = completed+paid, 1 = rejected, 2 = expired.
    function runJob(address client, address provider, address evaluator, uint256 amount, uint8 outcome, bytes32 reason) external {
        uint256 jobId = nextJobId++;
        emit JobCreated(jobId, client, provider, evaluator, block.timestamp + 1 days, address(0));
        emit JobFunded(jobId, client, provider, amount);
        if (outcome == 0) {
            emit JobSubmitted(jobId, provider, reason);
            emit JobCompleted(jobId, evaluator, reason);
            emit PaymentReleased(jobId, provider, amount);
        } else if (outcome == 1) {
            emit JobSubmitted(jobId, provider, reason);
            emit JobRejected(jobId, evaluator, reason);
        } else {
            emit JobExpired(jobId);
        }
    }
}
