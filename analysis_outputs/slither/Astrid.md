# Astrid - Security Analysis (Trace + Slither)

# Security Incident Analysis Report

## Attack Overview
The attack appears to be a contract creation exploit, potentially involving proxy contract manipulation. The attacker deploys a contract and interacts with it. The victim contract is likely a proxy contract that was compromised through an upgrade function.

## Contract Identification
- Attacker Contract: `0x792eC27874E1F614e757A1ae49d00ef5B2C73959` - This is the contract that initiates the attack by deploying a new contract and receiving funds.
- Victim Contract: `0xbAa87546cF87b5De1b0b52353A86792D40b8BA70` - This is an ERC1967Proxy contract. The slither report highlights potential issues with the `_upgradeToAndCall` and `_upgradeBeaconToAndCall` functions, which are common attack vectors in proxy contract exploits. The fact that the attacker receives funds before deploying the contract suggests that the attacker is using the funds to pay for the gas fees for the contract deployment.
- Helper Contracts: `0x09f2544778001407ba1dff71fa22c37f77abb186`, `0x18d06dbf8e0926110c9202136a78c3ae151461db`, `0xe26d01d3c0167d668a74276b18d9af89e84cd910` - These are contracts created during the execution of transaction `0x8af9b5fb3e2e3df8659ffb2e0f0c1f4c90d5a80f4f6fccef143b823ce673fb60`, which is the contract creation transaction initiated by the attacker. These contracts are likely part of the exploit.

## Vulnerability Analysis
The vulnerability lies in the potential for unauthorized upgrades of the proxy contract. The `ERC1967Proxy` contract relies on delegate calls to an implementation contract. If the implementation address can be changed by an unauthorized party, malicious code can be executed in the context of the proxy contract.

The Slither report identifies the following functions as potential vulnerabilities:

```solidity
ERC1967Upgrade._upgradeToAndCall(address,bytes,bool) (crytic-export/etherscan-contracts/0xbAa87546cF87b5De1b0b52353A86792D40b8BA70-ERC1967Proxy.sol#447-456) ignores return value by Address.functionDelegateCall(newImplementation,data) (crytic-export/etherscan-contracts/0xbAa87546cF87b5De1b0b52353A86792D40b8BA70-ERC1967Proxy.sol#454)
ERC1967Upgrade._upgradeBeaconToAndCall(address,bytes,bool) (crytic-export/etherscan-contracts/0xbAa87546cF87b5De1b0b52353A86792D40b8BA70-ERC1967Proxy.sol#556-566) ignores return value by Address.functionDelegateCall(IBeacon(newBeacon).implementation(),data) (crytic-export/etherscan-contracts/0xbAa87546cF87b5De1b0b52353A86792D40b8BA70-ERC1967Proxy.sol#564)
```

The `_upgradeToAndCall` function allows upgrading the implementation contract and calling a function on the new implementation in a single transaction. If the `newImplementation` address is controlled by the attacker, they can execute arbitrary code within the proxy's context. The `_upgradeBeaconToAndCall` function is similar, but uses a beacon contract to determine the implementation.

## Exploitation Mechanism
1. **Fund Attacker:** The attacker receives `1108389279355874825` wei from `0xbD78b7bC564C1db69418981aBaf35BCd9312e081` in transaction `0x7924f78793d6b95d61434fdbe64e3f17a4d3175d2fd78fa60c3c7ce87612171a`. This likely funds the attacker's contract for subsequent transactions.

2. **Deploy Malicious Contract:** The attacker deploys a contract named `_SIMONdotBLACK_(int16,uint80,bytes19[],uint56[],bytes29[])` in transaction `0x8af9b5fb3e2e3df8659ffb2e0f0c1f4c90d5a80f4f6fccef143b823ce673fb60`. This contract likely contains malicious code designed to exploit the `ERC1967Proxy` contract. The trace shows that this transaction also creates three other contracts: `0x09f2544778001407ba1dff71fa22c37f77abb186`, `0x18d06dbf8e0926110c9202136a78c3ae151461db`, and `0xe26d01d3c0167d668a74276b18d9af89e84cd910`. These contracts are likely helper contracts used in the exploit.

3. **Upgrade Proxy:** The attacker likely calls the `_upgradeToAndCall` function on the `ERC1967Proxy` contract, setting the `newImplementation` address to the address of the malicious contract deployed in step 2. The `data` parameter of `_upgradeToAndCall` might contain a function call to further exploit the proxy contract. The trace shows that `0xdc24316b9ae028f1497c275eb9192a3ea0f67022` and `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` transfer value to `0xb2e855411f67378c08f47401eacff37461e16188` which then transfers value to the attacker's contract `0x792eC27874E1F614e757A1ae49d00ef5B2C73959`.

4. **Drain Funds:** Once the malicious contract is set as the implementation, the attacker can execute arbitrary code within the proxy's context, potentially draining funds or performing other malicious actions.

5. **Further Interactions:** The transactions `0x6e5174bc75de88625c6c00680894009fdc8f7546741b3df4bdcfb4b930903c44` and `0xa56fdb1fc7c192b23cda44901d2871289cf28831cb94ccc731d089d4fb593793` from `0xcBf060349B8F56ce80Bd559E3999Aad55128D1aA` to the attacker contract `0x792eC27874E1F614e757A1ae49d00ef5B2C73959` with input `0x57652c20` are likely related to the attacker further exploiting the compromised contract.

**Rugpull Detection:**

Based on the available data, there is no direct evidence of a rugpull in the traditional sense (e.g., liquidity removal). However, the exploitation of the proxy contract to drain funds could be considered a form of rugpull, as it effectively deprives users of their assets. The deployment of a malicious contract and subsequent upgrade of the proxy contract strongly suggests malicious intent. The sudden transfer of funds to the attacker's contract after the proxy upgrade is a key indicator of a rugpull-like event.
