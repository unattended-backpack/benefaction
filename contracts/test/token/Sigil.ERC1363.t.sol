// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.26;

import { SigilTestBase } from "./utils/SigilTestBase.sol";
import { IERC1363 } from "token/interfaces/IERC1363.sol";
import { IERC1363Receiver } from "token/interfaces/IERC1363Receiver.sol";
import { IERC1363Spender } from "token/interfaces/IERC1363Spender.sol";
import { Sigil } from "token/Sigil.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title ValidReceiver
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A valid ERC-1363 receiver that returns the correct selector and tracks
  received transfers.

  @custom:date January 28th, 2026.
*/
contract ValidReceiver is
  IERC1363Receiver {

  /// The last operator that called onTransferReceived.
  address public lastOperator;

  /// The last sender of received tokens.
  address public lastFrom;

  /// The last amount received.
  uint256 public lastValue;

  /// The last data received.
  bytes public lastData;

  /// The number of times onTransferReceived was called.
  uint256 public callCount;

  /**
    Handle the receipt of ERC-1363 tokens.

    @param _operator The address that initiated the transfer.
    @param _from The address the tokens are transferred from.
    @param _value The amount of tokens transferred.
    @param _data Additional data.

    @return _ The function selector.
  */
  function onTransferReceived (
    address _operator,
    address _from,
    uint256 _value,
    bytes calldata _data
  ) external returns (bytes4) {
    lastOperator = _operator;
    lastFrom = _from;
    lastValue = _value;
    lastData = _data;
    callCount++;
    return IERC1363Receiver.onTransferReceived.selector;
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title InvalidReceiver
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  An invalid ERC-1363 receiver that returns the wrong selector.

  @custom:date January 28th, 2026.
*/
contract InvalidReceiver is
  IERC1363Receiver {

  /**
    Handle the receipt of ERC-1363 tokens but return wrong selector.

    @return _ The wrong selector.
  */
  function onTransferReceived (
    address,
    address,
    uint256,
    bytes calldata
  ) external pure returns (bytes4) {
    return bytes4(0xdeadbeef);
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title RevertingReceiver
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  An ERC-1363 receiver that always reverts with a message.

  @custom:date January 28th, 2026.
*/
contract RevertingReceiver is
  IERC1363Receiver {

  /**
    Handle the receipt of ERC-1363 tokens by reverting.

    @return _ Revert instead of returning a selector.
  */
  function onTransferReceived (
    address,
    address,
    uint256,
    bytes calldata
  ) external pure returns (bytes4) {
    revert("receiver rejected");
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title SilentRevertingReceiver
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  An ERC-1363 receiver that reverts without a message.

  @custom:date January 28th, 2026.
*/
contract SilentRevertingReceiver is
  IERC1363Receiver {

  /**
    Handle the receipt of ERC-1363 tokens by reverting silently.

    @return _ Revert without returning a selector.
  */
  function onTransferReceived (
    address,
    address,
    uint256,
    bytes calldata
  ) external pure returns (bytes4) {
    revert();
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title ValidSpender
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A valid ERC-1363 spender that returns the correct selector and tracks
  received approvals.

  @custom:date January 28th, 2026.
*/
contract ValidSpender is
  IERC1363Spender {

  /// The last owner that approved tokens.
  address public lastOwner;

  /// The last amount approved.
  uint256 public lastValue;

  /// The last data received.
  bytes public lastData;

  /// The number of times onApprovalReceived was called.
  uint256 public callCount;

  /**
    Handle approval of ERC-1363 tokens.

    @param _owner The address that approved the tokens.
    @param _value The amount of tokens approved.
    @param _data Additional data.

    @return _ The function selector.
  */
  function onApprovalReceived (
    address _owner,
    uint256 _value,
    bytes calldata _data
  ) external returns (bytes4) {
    lastOwner = _owner;
    lastValue = _value;
    lastData = _data;
    callCount++;
    return IERC1363Spender.onApprovalReceived.selector;
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title InvalidSpender
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  An invalid ERC-1363 spender that returns the wrong selector.

  @custom:date January 28th, 2026.
*/
contract InvalidSpender is
  IERC1363Spender {

  /**
    Handle approval but return wrong selector.

    @return _ The wrong selector.
  */
  function onApprovalReceived (
    address,
    uint256,
    bytes calldata
  ) external pure returns (bytes4) {
    return bytes4(0xdeadbeef);
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title RevertingSpender
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  An ERC-1363 spender that always reverts with a message.

  @custom:date January 28th, 2026.
*/
contract RevertingSpender is
  IERC1363Spender {

  /**
    Handle approval by reverting.

    @return _ Revert without returning a selector.
  */
  function onApprovalReceived (
    address,
    uint256,
    bytes calldata
  ) external pure returns (bytes4) {
    revert("spender rejected");
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title NonReceiverContract
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A contract that does not implement IERC1363Receiver.

  @custom:date January 28th, 2026.
*/
contract NonReceiverContract {

  /**
    A dummy function to ensure this contract has code.

    @return _ Return 42.
  */
  function dummy () external pure returns (uint256) {
    return 42;
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title ReentrantReceiver
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  An ERC-1363 receiver that attempts to reenter the token contract during the
  callback by calling transferAndCall again.

  @custom:date January 29th, 2026.
*/
contract ReentrantReceiver is
  IERC1363Receiver {

  /// The token contract to reenter.
  Sigil public token;

  /// The target to forward tokens to.
  ValidReceiver public forwardTarget;

  /// The number of times onTransferReceived was called.
  uint256 public callCount;

  /// Whether reentrancy should be attempted.
  bool public shouldReenter;

  /**
    Construct the reentrant receiver.

    @param _token The token contract.
    @param _forwardTarget The target to forward tokens to on reentry.
  */
  constructor (
    Sigil _token,
    ValidReceiver _forwardTarget
  ) {
    token = _token;
    forwardTarget = _forwardTarget;
    shouldReenter = true;
  }

  /**
    Enable or disable reentrancy attempts.

    @param _shouldReenter Whether to attempt reentrancy.
  */
  function setReenter (
    bool _shouldReenter
  ) external {
    shouldReenter = _shouldReenter;
  }

  /**
    Handle the receipt of ERC-1363 tokens. If reentrancy is enabled and we have
    a balance, forward half of it to the forward target.

    @param _value The amount of tokens transferred.

    @return _ The function selector.
  */
  function onTransferReceived (
    address,
    address,
    uint256 _value,
    bytes calldata
  ) external returns (bytes4) {
    callCount++;

    // If reentrancy is enabled and we received tokens, forward half.
    if (shouldReenter && _value > 0) {
      shouldReenter = false;
      uint256 _forwardAmount = _value / 2;
      if (_forwardAmount > 0) {
        token.transferAndCall(address(forwardTarget), _forwardAmount);
      }
    }
    return IERC1363Receiver.onTransferReceived.selector;
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Tests for ERC-1363 functionality.
  @author Tim Clancy <tim-clancy.eth>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  Test that the ERC-1363 implementation works correctly.

  @custom:date January 28th, 2026.
*/
contract SigilERC1363Test is
  SigilTestBase {

  /// A valid receiver contract.
  ValidReceiver public validReceiver;

  /// An invalid receiver contract.
  InvalidReceiver public invalidReceiver;

  /// A reverting receiver contract.
  RevertingReceiver public revertingReceiver;

  /// A silently reverting receiver contract.
  SilentRevertingReceiver public silentRevertingReceiver;

  /// A valid spender contract.
  ValidSpender public validSpender;

  /// An invalid spender contract.
  InvalidSpender public invalidSpender;

  /// A reverting spender contract.
  RevertingSpender public revertingSpender;

  /// A contract that doesn't implement the receiver interface.
  NonReceiverContract public nonReceiver;

  /// A receiver that attempts reentrancy.
  ReentrantReceiver public reentrantReceiver;

  /// Store Alice's address.
  address internal alice;

  /// Store Bob's address (an EOA).
  address internal bob;

  /// Set up the test.
  function setUp () public {
    _setUpSigil();
    validReceiver = new ValidReceiver();
    invalidReceiver = new InvalidReceiver();
    revertingReceiver = new RevertingReceiver();
    silentRevertingReceiver = new SilentRevertingReceiver();
    validSpender = new ValidSpender();
    invalidSpender = new InvalidSpender();
    revertingSpender = new RevertingSpender();
    nonReceiver = new NonReceiverContract();
    reentrantReceiver = new ReentrantReceiver(token, validReceiver);
    alice = makeAddr("alice");
    bob = makeAddr("bob");
    token.transfer(alice, 500 ether);
  }

  /// supportsInterface returns true for ERC-165.
  function test_supportsInterface_erc165 () public view {
    assertTrue(token.supportsInterface(0x01ffc9a7));
  }

  /// supportsInterface returns true for ERC-1363.
  function test_supportsInterface_erc1363 () public view {
    assertTrue(token.supportsInterface(0xb0202a11));
  }

  /// supportsInterface returns false for unknown interface.
  function test_supportsInterface_unknown () public view {
    assertFalse(token.supportsInterface(0xdeadbeef));
  }

  /// transferAndCall succeeds with valid receiver.
  function test_transferAndCall_validReceiver () public {
    uint256 _amount = 100 ether;
    bool _result = token.transferAndCall(address(validReceiver), _amount);
    assertTrue(_result);
    assertEq(token.balanceOf(address(validReceiver)), _amount);
    assertEq(validReceiver.lastOperator(), address(this));
    assertEq(validReceiver.lastFrom(), address(this));
    assertEq(validReceiver.lastValue(), _amount);
    assertEq(validReceiver.lastData(), "");
    assertEq(validReceiver.callCount(), 1);
  }

  /// transferAndCall succeeds with valid receiver and data.
  function test_transferAndCall_validReceiver_withData () public {
    uint256 _amount = 100 ether;
    bytes memory _data = "hello";
    bool _result =
      token.transferAndCall(address(validReceiver), _amount, _data);
    assertTrue(_result);
    assertEq(token.balanceOf(address(validReceiver)), _amount);
    assertEq(validReceiver.lastData(), _data);
  }

  /// transferAndCall reverts with EOA receiver.
  function test_transferAndCall_eoa_reverts () public {
    vm.expectRevert(IERC1363.EmptyTarget.selector);
    token.transferAndCall(bob, 100 ether);
  }

  /// transferAndCall reverts with invalid receiver (wrong selector).
  function test_transferAndCall_invalidReceiver_reverts () public {
    vm.expectRevert(IERC1363.InvalidReceiver.selector);
    token.transferAndCall(address(invalidReceiver), 100 ether);
  }

  /// transferAndCall reverts with reverting receiver (bubbles up error).
  function test_transferAndCall_revertingReceiver_reverts () public {
    vm.expectRevert("receiver rejected");
    token.transferAndCall(address(revertingReceiver), 100 ether);
  }

  /// transferAndCall reverts with silently reverting receiver.
  function test_transferAndCall_silentRevertingReceiver_reverts () public {
    vm.expectRevert(IERC1363.InvalidReceiver.selector);
    token.transferAndCall(address(silentRevertingReceiver), 100 ether);
  }

  /// transferAndCall reverts with non-receiver contract.
  function test_transferAndCall_nonReceiverContract_reverts () public {
    vm.expectRevert(IERC1363.InvalidReceiver.selector);
    token.transferAndCall(address(nonReceiver), 100 ether);
  }

  /// transferAndCall reverts with insufficient balance.
  function test_transferAndCall_insufficientBalance_reverts () public {
    vm.expectRevert();
    token.transferAndCall(address(validReceiver), 2_000_000_000 ether);
  }

  /// transferFromAndCall succeeds with valid receiver.
  function test_transferFromAndCall_validReceiver () public {
    uint256 _amount = 100 ether;
    vm.prank(alice);
    token.approve(address(this), _amount);
    bool _result =
      token.transferFromAndCall(alice, address(validReceiver), _amount);
    assertTrue(_result);
    assertEq(token.balanceOf(address(validReceiver)), _amount);
    assertEq(validReceiver.lastOperator(), address(this));
    assertEq(validReceiver.lastFrom(), alice);
    assertEq(validReceiver.lastValue(), _amount);
    assertEq(validReceiver.callCount(), 1);
  }

  /// transferFromAndCall succeeds with valid receiver and data.
  function test_transferFromAndCall_validReceiver_withData () public {
    uint256 _amount = 100 ether;
    bytes memory _data = "world";
    vm.prank(alice);
    token.approve(address(this), _amount);
    bool _result =
      token.transferFromAndCall(alice, address(validReceiver), _amount, _data);
    assertTrue(_result);
    assertEq(validReceiver.lastData(), _data);
  }

  /// transferFromAndCall reverts with EOA receiver.
  function test_transferFromAndCall_eoa_reverts () public {
    vm.prank(alice);
    token.approve(address(this), 100 ether);
    vm.expectRevert(IERC1363.EmptyTarget.selector);
    token.transferFromAndCall(alice, bob, 100 ether);
  }

  /// transferFromAndCall reverts with invalid receiver.
  function test_transferFromAndCall_invalidReceiver_reverts () public {
    vm.prank(alice);
    token.approve(address(this), 100 ether);
    vm.expectRevert(IERC1363.InvalidReceiver.selector);
    token.transferFromAndCall(alice, address(invalidReceiver), 100 ether);
  }

  /// transferFromAndCall reverts with reverting receiver.
  function test_transferFromAndCall_revertingReceiver_reverts () public {
    vm.prank(alice);
    token.approve(address(this), 100 ether);
    vm.expectRevert("receiver rejected");
    token.transferFromAndCall(alice, address(revertingReceiver), 100 ether);
  }

  /// transferFromAndCall reverts without allowance.
  function test_transferFromAndCall_noAllowance_reverts () public {
    vm.expectRevert();
    token.transferFromAndCall(alice, address(validReceiver), 100 ether);
  }

  /// approveAndCall succeeds with valid spender.
  function test_approveAndCall_validSpender () public {
    uint256 _amount = 100 ether;
    bool _result = token.approveAndCall(address(validSpender), _amount);
    assertTrue(_result);
    assertEq(token.allowance(address(this), address(validSpender)), _amount);
    assertEq(validSpender.lastOwner(), address(this));
    assertEq(validSpender.lastValue(), _amount);
    assertEq(validSpender.lastData(), "");
    assertEq(validSpender.callCount(), 1);
  }

  /// approveAndCall succeeds with valid spender and data.
  function test_approveAndCall_validSpender_withData () public {
    uint256 _amount = 100 ether;
    bytes memory _data = "approval data";
    bool _result = token.approveAndCall(address(validSpender), _amount, _data);
    assertTrue(_result);
    assertEq(validSpender.lastData(), _data);
  }

  /// approveAndCall reverts with EOA spender.
  function test_approveAndCall_eoa_reverts () public {
    vm.expectRevert(IERC1363.EmptyTarget.selector);
    token.approveAndCall(bob, 100 ether);
  }

  /// approveAndCall reverts with invalid spender (wrong selector).
  function test_approveAndCall_invalidSpender_reverts () public {
    vm.expectRevert(IERC1363.InvalidSpender.selector);
    token.approveAndCall(address(invalidSpender), 100 ether);
  }

  /// approveAndCall reverts with reverting spender (bubbles up error).
  function test_approveAndCall_revertingSpender_reverts () public {
    vm.expectRevert("spender rejected");
    token.approveAndCall(address(revertingSpender), 100 ether);
  }

  /// approveAndCall reverts with non-spender contract.
  function test_approveAndCall_nonSpenderContract_reverts () public {
    vm.expectRevert(IERC1363.InvalidSpender.selector);
    token.approveAndCall(address(nonReceiver), 100 ether);
  }

  /// transferAndCall with zero amount succeeds.
  function test_transferAndCall_zeroAmount () public {
    bool _result = token.transferAndCall(address(validReceiver), 0);
    assertTrue(_result);
    assertEq(validReceiver.lastValue(), 0);
    assertEq(validReceiver.callCount(), 1);
  }

  /// approveAndCall with zero amount succeeds.
  function test_approveAndCall_zeroAmount () public {
    bool _result = token.approveAndCall(address(validSpender), 0);
    assertTrue(_result);
    assertEq(validSpender.lastValue(), 0);
    assertEq(validSpender.callCount(), 1);
  }

  /// Multiple transferAndCall calls accumulate correctly.
  function test_transferAndCall_multipleCalls () public {
    token.transferAndCall(address(validReceiver), 10 ether);
    token.transferAndCall(address(validReceiver), 20 ether);
    token.transferAndCall(address(validReceiver), 30 ether);
    assertEq(token.balanceOf(address(validReceiver)), 60 ether);
    assertEq(validReceiver.callCount(), 3);
    assertEq(validReceiver.lastValue(), 30 ether);
  }

  /// approveAndCall overwrites previous allowance.
  function test_approveAndCall_overwritesAllowance () public {
    token.approveAndCall(address(validSpender), 100 ether);
    assertEq(token.allowance(address(this), address(validSpender)), 100 ether);
    token.approveAndCall(address(validSpender), 50 ether);
    assertEq(token.allowance(address(this), address(validSpender)), 50 ether);
    assertEq(validSpender.callCount(), 2);
  }

  /// transferAndCall reverts with address(0) as receiver.
  function test_transferAndCall_addressZero_reverts () public {
    vm.expectRevert(IERC1363.EmptyTarget.selector);
    token.transferAndCall(address(0), 100 ether);
  }

  /// approveAndCall reverts with address(0) as spender.
  function test_approveAndCall_addressZero_reverts () public {
    vm.expectRevert(IERC1363.EmptyTarget.selector);
    token.approveAndCall(address(0), 100 ether);
  }

  /// Reentrancy during transferAndCall callback succeeds with correct balances.
  function test_transferAndCall_reentrancy () public {
    uint256 _amount = 100 ether;

    // Transfer to reentrant receiver, which will forward half to validReceiver.
    token.transferAndCall(address(reentrantReceiver), _amount);

    // Reentrant receiver should have been called once.
    assertEq(reentrantReceiver.callCount(), 1);

    // Valid receiver should have been called once (from the reentrant forward).
    assertEq(validReceiver.callCount(), 1);

    // Reentrant receiver keeps half, forwards half.
    assertEq(token.balanceOf(address(reentrantReceiver)), _amount / 2);
    assertEq(token.balanceOf(address(validReceiver)), _amount / 2);
  }
}

