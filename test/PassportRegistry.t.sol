// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PassportRegistry} from "../src/PassportRegistry.sol";

/// @dev Minimal mock of the SPACE ID Agent ID registry surface used by PassportRegistry.
contract MockAgentID {
    mapping(string => address) private _ownerOfHandle;
    mapping(address => string) private _handleOf;

    event Registered(string handle, address owner);

    function register(string calldata handle, address owner) external {
        require(owner != address(0), "zero owner");
        require(_ownerOfHandle[handle] == address(0), "taken");
        require(bytes(_handleOf[owner]).length == 0, "soulbound: one per wallet");
        _ownerOfHandle[handle] = owner;
        _handleOf[owner] = handle;
        emit Registered(handle, owner);
    }

    function ownerOfHandle(string calldata handle) external view returns (address) {
        return _ownerOfHandle[handle];
    }

    function handleOf(address owner) external view returns (string memory) {
        return _handleOf[owner];
    }
}

contract PassportRegistryTest is Test {
    MockAgentID internal agentId;
    PassportRegistry internal registry;

    uint256 internal constant INDEXER_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address internal indexer = vm.addr(INDEXER_KEY);

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob"); // has no Agent ID

    function setUp() public {
        agentId = new MockAgentID();
        registry = new PassportRegistry(address(agentId), indexer);
        agentId.register("alice", alice);
    }

    // ── Claim gate ──────────────────────────────────────────────────────

    function test_claim_requires_agent_id() public {
        vm.expectRevert(PassportRegistry.NoAgentID.selector);
        vm.prank(bob);
        registry.claim();
    }

    function test_claim_with_agent_id() public {
        vm.prank(alice);
        registry.claim();
        assertTrue(registry.claimed(alice));
    }

    // ── Stats updates ───────────────────────────────────────────────────

    function _sign(address agent, uint64 c, uint64 rj, uint64 e, uint128 vol, uint64 ts, uint64 epoch)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = keccak256(abi.encode(agent, c, rj, e, vol, ts, epoch));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(INDEXER_KEY, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function test_updateStats_happy_path() public {
        vm.prank(alice);
        registry.claim();

        vm.prank(indexer);
        registry.updateStats(alice, 5, 1, 0, 123e18, 1700000000, _sign(alice, 5, 1, 0, 123e18, 1700000000, 1));

        (address wallet, PassportRegistry.Stats memory s, string memory rev) =
            registry.resolve("ALICE"); // uppercase input -> normalized inside
        assertEq(wallet, alice);
        assertEq(s.completedJobs, 5);
        assertEq(s.rejectedJobs, 1);
        assertEq(s.totalVolumeRaw, 123e18);
        assertEq(rev, "alice");
    }

    function test_updateStats_rejects_non_indexer_caller() public {
        vm.prank(alice);
        registry.claim();

        bytes memory sig = _sign(alice, 1, 0, 0, 1e18, 1, 1);
        vm.prank(alice);
        vm.expectRevert(PassportRegistry.NotIndexer.selector);
        registry.updateStats(alice, 1, 0, 0, 1e18, 1, sig);
    }

    function test_updateStats_rejects_forged_signature() public {
        vm.prank(alice);
        registry.claim();

        uint256 fakeKey = 0xdead;
        bytes32 digest = keccak256(abi.encode(alice, uint64(1), uint64(0), uint64(0), uint128(1e18), uint64(1), uint64(1)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fakeKey, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(indexer);
        vm.expectRevert(PassportRegistry.BadSignature.selector);
        registry.updateStats(alice, 1, 0, 0, 1e18, 1, sig);
    }

    function test_updateStats_rejects_unclaimed_passport() public {
        address carol = makeAddr("carol");
        agentId.register("carol", carol); // registered but never claimed

        bytes memory sig = _sign(carol, 1, 0, 0, 1e18, 1, 1);
        vm.prank(indexer);
        vm.expectRevert(PassportRegistry.NotClaimed.selector);
        registry.updateStats(carol, 1, 0, 0, 1e18, 1, sig);
    }

    function test_updateStats_rejects_stale_watermark() public {
        vm.prank(alice);
        registry.claim();

        vm.prank(indexer);
        registry.updateStats(alice, 1, 0, 0, 1e18, 100, _sign(alice, 1, 0, 0, 1e18, 100, 1));

        vm.prank(indexer);
        vm.expectRevert(PassportRegistry.StaleStats.selector);
        registry.updateStats(alice, 2, 0, 0, 2e18, 99, _sign(alice, 2, 0, 0, 2e18, 99, 2));
    }

    // ── Resolution ──────────────────────────────────────────────────────

    function test_resolve_unknown_handle_returns_zero() public view {
        (address wallet, PassportRegistry.Stats memory s, ) = registry.resolve("ghost");
        assertEq(wallet, address(0));
        assertEq(s.completedJobs, 0);
    }

    function test_resolve_unclaimed_wallet_returns_zeroed_stats() public {
        address dave = makeAddr("dave");
        agentId.register("dave", dave);

        (address wallet, PassportRegistry.Stats memory s, string memory rev) = registry.resolve("dave");
        assertEq(wallet, dave);
        assertEq(s.completedJobs, 0);
        assertEq(rev, "dave");
    }

    // ── Indexer rotation ────────────────────────────────────────────────

    function test_indexer_rotation_two_step() public {
        uint256 nextKey = 0xfeed;
        address next = vm.addr(nextKey);

        vm.prank(indexer);
        registry.setIndexer(next);
        vm.prank(next);
        registry.acceptIndexer();
        assertEq(registry.indexer(), next);

        // new indexer can write; old one cannot
        vm.prank(alice);
        registry.claim();
        bytes32 digest = keccak256(abi.encode(alice, uint64(1), uint64(0), uint64(0), uint128(1e18), uint64(1), uint64(1)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(nextKey, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);
        vm.prank(next);
        registry.updateStats(alice, 1, 0, 0, 1e18, 1, sig);

        vm.prank(indexer);
        vm.expectRevert(PassportRegistry.NotIndexer.selector);
        registry.updateStats(alice, 2, 0, 0, 2e18, 2, _sign(alice, 2, 0, 0, 2e18, 2, 2));
    }
}
