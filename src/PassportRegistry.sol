// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title PassportRegistry — on-chain reputation passport for BNB Chain Agent IDs
/// @notice Passports are keyed by agent wallets that hold a soulbound Agent ID
///         handle (SPACE ID Agent ID registry). Facts (job outcomes) are written
///         by an authorized indexer; scores are computed off-chain from facts.
interface IAgentID {
    /// @notice handle -> owner. Returns address(0) when unregistered. Input must be normalized lowercase.
    function ownerOfHandle(string calldata handle) external view returns (address);
    /// @notice owner -> handle. Returns "" when none. Soulbound => authoritative.
    function handleOf(address owner) external view returns (string memory);
}

contract PassportRegistry {
    // ── Immutable wiring ────────────────────────────────────────────────
    IAgentID public immutable AGENT_ID;

    // ── Indexer (two-step rotation: set -> accept) ──────────────────────
    address public indexer;
    mapping(address => bool) public pendingIndexer;

    // ── Passport data ───────────────────────────────────────────────────
    struct Stats {
        uint64 completedJobs;
        uint64 rejectedJobs;
        uint64 expiredJobs;
        uint128 totalVolumeRaw; // payment token raw units
        uint64 lastSettledAt;   // monotonic watermark
        uint64 epoch;           // per-passport anti-replay counter
    }

    mapping(address => Stats) public passports;
    mapping(address => bool) public claimed;

    // ── Events ──────────────────────────────────────────────────────────
    event PassportClaimed(address indexed agentWallet, string handle);
    event StatsUpdated(address indexed agentWallet, Stats stats);
    event IndexerSet(address indexed current, address indexed next);
    event IndexerAccepted(address indexed previous, address indexed next);

    // ── Errors ──────────────────────────────────────────────────────────
    error NoAgentID();
    error NotClaimed();
    error BadSignature();
    error StaleStats();
    error NotIndexer();
    error NotPending();

    constructor(address agentIdRegistry, address initialIndexer) {
        AGENT_ID = IAgentID(agentIdRegistry);
        indexer = initialIndexer;
    }

    /// @notice Claim a passport. Requires the caller to hold a soulbound Agent ID handle.
    function claim() external {
        string memory handle = AGENT_ID.handleOf(msg.sender);
        require(bytes(handle).length > 0, NoAgentID());
        claimed[msg.sender] = true;
        emit PassportClaimed(msg.sender, handle);
    }

    /// @notice Write indexer-signed facts for a claimed passport.
    ///         sig = EIP-191 personal_sign over
    ///         keccak256(abi.encode(agent, completed, rejected, expired, volume, lastSettled, nextEpoch))
    function updateStats(
        address agent,
        uint64 completed,
        uint64 rejected,
        uint64 expired,
        uint128 volume,
        uint64 lastSettled,
        bytes calldata sig
    ) external {
        require(claimed[agent], NotClaimed());
        if (msg.sender != indexer) revert NotIndexer();

        Stats storage s = passports[agent];
        uint64 nextEpoch = s.epoch + 1;

        bytes32 digest = keccak256(
            abi.encode(agent, completed, rejected, expired, volume, lastSettled, nextEpoch)
        );
        bytes32 ethHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );

        (bytes32 r, bytes32 sv, uint8 v) = _splitSig(sig);
        if (ecrecover(ethHash, v, r, sv) != indexer) revert BadSignature();
        if (lastSettled < s.lastSettledAt) revert StaleStats();

        s.completedJobs = completed;
        s.rejectedJobs = rejected;
        s.expiredJobs = expired;
        s.totalVolumeRaw = volume;
        s.lastSettledAt = lastSettled;
        s.epoch = nextEpoch;

        emit StatsUpdated(agent, s);
    }

    /// @notice Forward resolution inside the contract: handle -> wallet + facts + reverse handle.
    /// @return wallet address(0) when the handle is unregistered.
    /// @return s facts for the wallet (zeroed when unclaimed).
    /// @return reverseHandle authoritative soulbound handle for the wallet.
    function resolve(string calldata handle)
        external
        view
        returns (address wallet, Stats memory s, string memory reverseHandle)
    {
        wallet = AGENT_ID.ownerOfHandle(_normalize(handle));
        if (wallet == address(0)) {
            return (address(0), Stats(0, 0, 0, 0, 0, 0), "");
        }
        s = passports[wallet];
        reverseHandle = AGENT_ID.handleOf(wallet);
    }

    // ── Indexer rotation (two-step to avoid key bricking) ───────────────
    function setIndexer(address next) external {
        if (msg.sender != indexer) revert NotIndexer();
        pendingIndexer[next] = true;
        emit IndexerSet(indexer, next);
    }

    function acceptIndexer() external {
        if (!pendingIndexer[msg.sender]) revert NotPending();
        pendingIndexer[msg.sender] = false;
        emit IndexerAccepted(indexer, msg.sender);
        indexer = msg.sender;
    }

    // ── Internals ───────────────────────────────────────────────────────
    function _splitSig(bytes calldata sig)
        private
        pure
        returns (bytes32 r, bytes32 sv, uint8 v)
    {
        require(sig.length == 65, BadSignature());
        assembly {
            r := calldataload(sig.offset)
            sv := calldataload(add(sig.offset, 32))
            v := shr(248, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
    }

    /// @notice ASCII-only lowercase normalization (a-z0-9 handles).
    function _normalize(string calldata h) private pure returns (string memory) {
        bytes memory b = bytes(h);
        for (uint256 i; i < b.length; i++) {
            if (b[i] >= 0x41 && b[i] <= 0x5A) b[i] = bytes1(uint8(b[i]) + 32);
        }
        return string(b);
    }
}
