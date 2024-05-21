// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.0;

import { Test } from "forge-std/Test.sol";

import { Utils, WebAuthnInfo } from "webauthn-sol/../test/Utils.sol";
import { WebAuthn } from "webauthn-sol/WebAuthn.sol";

/// @dev Some comment.
contract SnapshotTest is Test {
  using Utils for uint256;
  using Utils for bytes32;

  uint256 internal constant PRIVATE_KEY = uint256(0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874fd2);
  PublicKey public PUBLIC_KEY = abi.decode(
    hex"1c05286fe694493eae33312f2d2e0d0abeda8db76238b7a204be1fb87f54ce4228fef61ef4ac300f631657635c28e59bfb2fe71bce1634c81c65642042f6dc4d",
    (PublicKey)
  );

  function test_snapshot(UserOperation calldata userOp) external {
    bytes32 userOpHash = keccak256(abi.encode(userOp));
    WebAuthnInfo memory webauthn = userOpHash.getWebAuthnStruct();
    (bytes32 r, bytes32 s) = vm.signP256(PRIVATE_KEY, webauthn.messageHash);
    assertTrue(
      WebAuthn.verify({
        challenge: abi.encode(userOpHash),
        requireUV: false,
        webAuthnAuth: WebAuthn.WebAuthnAuth({
          authenticatorData: webauthn.authenticatorData,
          clientDataJSON: webauthn.clientDataJSON,
          typeIndex: 1,
          challengeIndex: 23,
          r: uint256(r),
          s: uint256(s).normalizeS()
        }),
        x: PUBLIC_KEY.x,
        y: PUBLIC_KEY.y
      })
    );
  }
}

struct PublicKey {
  uint256 x;
  uint256 y;
}

struct UserOperation {
  bytes field0;
  bytes field1;
  uint256 field2;
  uint256 field3;
  uint256 field4;
}
