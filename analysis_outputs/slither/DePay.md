# DePay - Security Analysis (Trace + Slither)

# Security Incident Analysis Report

## Attack Overview
The attack appears to be an exploit of the DePay Router V1 contract (`0xae60aC8e69414C2Dc362D0e6a03af643d1D85b92`) leveraging a controlled delegatecall vulnerability. The attacker drained ETH from multiple addresses by routing it through the DePay Router.

## Contract Identification
- Attacker Contract: `0xae60aC8e69414C2Dc362D0e6a03af643d1D85b92` (DePayRouterV1). This contract is not the attacker's EOA, but rather a contract that was exploited. The attacker interacted with this contract to drain funds.
- Victim Contract: Based on the transaction traces, the victim is the DePayRouterV1 contract (`0xae60aC8e69414C2Dc362D0e6a03af643d1D85b92`). The traces show that the attacker sent ETH to this contract, which then called the Uniswap V2 Router (`0x7a250d5630b4cf539739df2c5dacb4c659f2488d`) and WETH (`0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2`). The Slither report identifies a controlled delegatecall vulnerability in the DePayRouterV1 contract.
- Helper Contracts: Uniswap V2 Router (`0x7a250d5630b4cf539739df2c5dacb4c659f2488d`) and WETH (`0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2`) are legitimate contracts used by the DePayRouterV1.

## Vulnerability Analysis
The Slither report highlights a critical vulnerability: **Controlled Delegatecall**.

```solidity
DePayRouterV1._execute(address[],uint256[],address[],address[],string[]) (crytic-export/etherscan-contracts/0xae60aC8e69414C2Dc362D0e6a03af643d1D85b92-DePayRouterV1.sol#784-808) uses delegatecall to a input-controlled function id
	- (success,returnData) = address(plugin).delegatecall(abi.encodeWithSelector(plugin.execute.selector,path,amounts,addresses,data)) (crytic-export/etherscan-contracts/0xae60aC8e69414C2Dc362D0e6a03af643d1D85b92-DePayRouterV1.sol#797-799)
```

This vulnerability exists in the `_execute` function of the `DePayRouterV1` contract. The function uses `delegatecall` to call a plugin contract, and the function selector (`plugin.execute.selector`) and the arguments passed to the plugin are controlled by the user's input. This allows an attacker to execute arbitrary code in the context of the `DePayRouterV1` contract.

## Exploitation Mechanism
The attacker exploited the controlled delegatecall vulnerability in the `_execute` function. The `route` function calls the `_execute` function in a loop. By crafting malicious input data for the `route` function, the attacker was able to control the `plugin` address and the `data` parameter passed to the `delegatecall`. This allowed the attacker to execute arbitrary code within the context of the `DePayRouterV1` contract, effectively gaining control over the contract's funds.

The transaction traces show that the attacker sent ETH to the `DePayRouterV1` contract. The contract then called the Uniswap V2 Router and WETH, likely as part of the malicious code injected through the delegatecall. This allowed the attacker to drain ETH from the `DePayRouterV1` contract.

The transactions show multiple transfers of ETH from different addresses to the attacker's contract, indicating that the attacker was able to drain funds from multiple sources by routing them through the vulnerable DePay Router.

## Rugpull Detection
There is no evidence of a rugpull in the provided data. The attacker exploited a vulnerability in the DePay Router contract, rather than manipulating the contract's ownership or privileged functions. The transactions do not show any suspicious activity by the contract owner, such as removing liquidity or modifying critical parameters.
