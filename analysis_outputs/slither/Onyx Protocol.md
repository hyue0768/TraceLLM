# Onyx Protocol - Security Analysis (Trace + Slither)

# Security Incident Analysis Report

## Attack Overview
The attack appears to be a rugpull leveraging a controlled delegatecall vulnerability in the `OErc20Delegator` contract. The attacker likely gained control of the implementation contract and then used the delegatecall functionality to drain funds.

## Contract Identification
- Attacker Contract: `0x085bDfF2C522e8637D4154039Db8746bb8642BfF` - This contract initiates the attack by calling the `OErc20Delegator` contract.
- Victim Contract: `0x526e8E98356194b64EaE4C2d443cC8AAD367336f` - This is identified as the victim because the attacker calls this contract first with the function `0xcb0d9b88`. Based on the Slither report, this is likely the `OErc20Delegator` contract. The trace shows that this contract then self-destructs, transferring a large amount of value to the attacker.
- Helper Contracts: Several contracts are created by the `OErc20Delegator` contract via `CREATE2` calls. These are likely malicious implementation contracts used to execute the attack.

## Vulnerability Analysis
The primary vulnerability lies in the `OErc20Delegator` contract's use of `delegatecall` with user-controlled data. The Slither report highlights this:

```
OErc20Delegator.delegateTo(address,bytes) (contracts/OErc20Delegator.sol#425-433) uses delegatecall to a input-controlled function id
	- (success,returnData) = callee.delegatecall(data) (contracts/OErc20Delegator.sol#426)

OErc20Delegator.fallback() (contracts/OErc20Delegator.sol#466-480) uses delegatecall to a input-controlled function id
	- (success,None) = implementation.delegatecall(msg.data) (contracts/OErc20Delegator.sol#470)
```

The `delegateTo` function allows an attacker to specify the target address and the data to be executed via `delegatecall`. This means the attacker can execute arbitrary code in the context of the `OErc20Delegator` contract, bypassing any access control restrictions. The `fallback` function also uses `delegatecall` to the implementation contract, which can be changed by the owner.

## Exploitation Mechanism
1. **Attacker Initiates Delegatecall:** The attacker calls the `OErc20Delegator` contract (`0x526e8E98356194b64EaE4C2d443cC8AAD367336f`) with the function `0xcb0d9b88` (Transaction `0xf7c21600452939a81b599017ee24ee0dfd92aaaccd0a55d02819a7658a6ef635`). This function is not identified in the provided Slither report, but it's likely a custom function that triggers the vulnerability.
2. **Implementation Contract Creation:** The `OErc20Delegator` contract creates several new contracts using the `CREATE2` opcode. These contracts are likely malicious implementations designed to drain funds.
3. **Value Transfer to Attacker:** The `OErc20Delegator` contract transfers a large amount of value (1156934745663858638915) to the attacker's address (`0x085bDfF2C522e8637D4154039Db8746bb8642BfF`).
4. **Self-Destruct:** The `OErc20Delegator` contract then self-destructs, effectively removing itself from the blockchain.

The transaction trace shows that the `OErc20Delegator` contract first transfers a large amount of value to the attacker and then self-destructs. This behavior is characteristic of a rugpull. The attacker likely used the `delegatecall` vulnerability to execute malicious code within the `OErc20Delegator` contract, allowing them to drain funds and then destroy the contract.
