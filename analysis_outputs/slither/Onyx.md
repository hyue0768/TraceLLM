# Onyx - Security Analysis (Trace + Slither)

# Security Incident Analysis Report

## Attack Overview
This incident appears to be an attempted exploit leveraging a controlled delegatecall vulnerability in the `NFTLiquidationProxy` contract. The attacker attempts to call arbitrary functions on the implementation contract through the proxy's fallback function. While the transaction data shows the attacker interacting with various contracts, the core vulnerability lies within the proxy pattern implementation of the `NFTLiquidationProxy` and `NFTLiquidation` contracts.

## Contract Identification
- Attacker Contract: `0x680910cf5Fc9969A25Fd57e7896A14fF1E55F36B` [This contract initiates the attack by creating contracts and calling functions on the victim contract.]
- Victim Contract: `0xf10Bc5bE84640236C71173D1809038af4eE19002` (`NFTLiquidationProxy`) [The proxy contract is the entry point for the attack due to its vulnerable `fallback` function. The proxy delegates calls to the implementation contract, `NFTLiquidation`.]
- Helper Contracts: `0xa57eDA20Be51Ae07Df3c8B92494C974a92cf8956` [This contract is created by the attacker and likely contains malicious code intended to be executed via the delegatecall.]

## Vulnerability Analysis
The primary vulnerability lies in the `NFTLiquidationProxy` contract's `fallback` function:

```solidity
  function () external payable {
    (bool success, ) = nftLiquidationImplementation.delegatecall(msg.data);
    require(success, "delegatecall failed");
  }
```

This function uses `delegatecall` to forward all calls to the `nftLiquidationImplementation` contract. The `msg.data` is directly passed to the implementation contract without any validation or sanitization. This allows an attacker to call any function in the implementation contract with arbitrary arguments, potentially bypassing access control restrictions and manipulating the contract's state in unintended ways.

The Slither analysis also highlights this vulnerability:

```
NFTLiquidationProxy.fallback() (crytic-export/etherscan-contracts/0xf10Bc5bE84640236C71173D1809038af4eE19002-NFTLiquidation.sol#192-204) uses delegatecall to a input-controlled function id
	- (success,None) = nftLiquidationImplementation.delegatecall(msg.data) (crytic-export/etherscan-contracts/0xf10Bc5bE84640236C71173D1809038af4eE19002-NFTLiquidation.sol#194)
```

## Exploitation Mechanism
The attacker exploits the controlled delegatecall by creating a malicious contract (`0xa57eDA20Be51Ae07Df3c8B92494C974a92cf8956`) and then calling the `NFTLiquidationProxy`'s fallback function with `msg.data` crafted to execute code within the context of the `NFTLiquidation` contract, but using the malicious logic from the attacker's contract.

The attack sequence is as follows:

1.  **Contract Creation:** The attacker deploys a contract (`0xa57eDA20Be51Ae07Df3c8B92494C974a92cf8956`) using transaction `0xd23691cdccd7a88d9864a224e19404f6609627b77f7eb57c9fdd7ec402b2813e`. This contract likely contains malicious code.
2.  **Delegatecall Attempt:** The attacker then attempts to exploit the `NFTLiquidationProxy` contract. The transaction `0xc19b050707db0ec4e3f229436c6f5d383f91ed7f521d90ee3e645eb741e31c11` calls the `NFTLiquidationProxy` contract, which then uses delegatecall to execute code from the attacker's contract (`0xa57eDA20Be51Ae07Df3c8B92494C974a92cf8956`).
3.  **Further Exploitation:** The transaction `0x46567c731c4f4f7e27c4ce591f0aebdeb2d9ae1038237a0134de7b13e63d8729` shows the attacker interacting with the `NFTLiquidationProxy` contract again, likely attempting to further exploit the delegatecall vulnerability.

The subsequent transactions show the attacker interacting with various other contracts, likely as part of the exploit attempt. The functions called, such as `borrow` and `redeemUnderlying`, suggest the attacker is trying to manipulate the lending and borrowing mechanisms of the protocol.

The transactions involving `execute(bytes,bytes[],uint256)` on contract `0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD` suggest the attacker is interacting with a Gnosis Safe or similar multi-signature wallet, possibly to gain control of the protocol's funds.

The transactions setting `_SIMONdotBLACK_` suggest the attacker is trying to set a malicious function selector.

## Rugpull Detection
Based on the provided information, there is no direct evidence of a rugpull. However, the attacker's actions are highly suspicious and indicate an attempt to exploit the protocol for personal gain. The attacker's deployment of a malicious contract and subsequent attempts to manipulate the protocol's state through delegatecall strongly suggest malicious intent. The attacker is likely attempting to drain funds from the protocol, which would effectively constitute a rugpull.
