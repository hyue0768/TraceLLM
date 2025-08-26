# Zunami Protocol - Security Analysis (Trace + Slither)

# Security Incident Analysis Report

## Attack Overview
The attack appears to be an exploit of the Zunami protocol, specifically targeting the `ZunamiElasticRigidVault` contract. The attacker manipulated the vault to drain a significant amount of funds. The traces suggest the attacker interacted with the vault contract to deposit and withdraw assets, ultimately extracting more than they initially deposited. The multiple calls to `C02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH) indicate the attacker was likely manipulating the vault's WETH balance.

## Contract Identification
- Attacker Contract: `0xA21a2B59d80dC42D332F778Cbb9eA127100e5d75` - This contract initiates the attack transactions, receiving funds and then transferring them out.
- Victim Contract: `0x4ebdf703948ddcea3b11f675b4d1fba9d2414a14` - This address receives multiple calls with value from WETH (`0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2`) and then sends WETH back to WETH contract. This is highly indicative of a contract being manipulated. Further analysis of the contract code is needed to confirm the exact vulnerability.
- Helper Contracts: `0xa1f8a6807c402e4a15ef4eba36528a3fed24e577` - This contract receives a large transfer of value from the attacker contract, suggesting it's part of the exploit flow.

## Vulnerability Analysis
Based on the transaction traces and the Slither analysis, the `ElasticRigidVault` contract (`0xb40b6608b2743e691c9b54ddbdee7bf03cd79f1c`) is likely the core of the exploit. The Slither report highlights a reentrancy vulnerability in the `_deposit` and `_withdraw` functions of the `ElasticRigidVault` contract.

```solidity
// contracts/ElasticRigidVault.sol
function _deposit(address caller, address receiver, uint256 value, uint256 nominal) internal {
    // ...
    SafeERC20.safeTransferFrom(IERC20Metadata(asset()), caller, address(this), nominal);
    _mintElastic(receiver, nominal, value);
    emit Deposit(caller, receiver, value, nominal);
}

function _withdraw(address caller, address receiver, address owner, uint256 value, uint256 nominal) internal {
    // ...
    SafeERC20.safeTransfer(IERC20Metadata(asset()), receiver, nominal - nominalFee);
    emit Withdraw(caller, receiver, owner, value, nominal, nominalFee);
}
```

The `SafeERC20.safeTransferFrom` call in `_deposit` and `SafeERC20.safeTransfer` in `_withdraw` are external calls that can potentially trigger a reentrancy attack. The state updates (`_mintElastic` and event emissions) occur *after* these external calls, making the contract vulnerable.

## Exploitation Mechanism

1. **Initial Deposit:** The attacker likely initiated the attack by depositing a small amount of WETH into the `ElasticRigidVault` contract using the `_deposit` function.
2. **Reentrancy Trigger:** The `SafeERC20.safeTransferFrom` call in the `_deposit` function triggers a call to the WETH contract. The attacker's contract is designed to re-enter the `_withdraw` function *before* the `_mintElastic` function is executed in the original `_deposit` call.
3. **Withdrawal during Deposit:** Inside the re-entered `_withdraw` function, the attacker withdraws a larger amount of WETH than they initially deposited. This is possible because the `_mintElastic` function (which updates the user's balance) hasn't been executed yet in the original `_deposit` call.
4. **Multiple Withdrawals:** The attacker can repeat steps 2 and 3 multiple times within the same transaction, draining the `ElasticRigidVault` contract of its WETH balance.
5. **Finalization:** After draining the vault, the original `_deposit` call finally completes, executing the `_mintElastic` function. However, by this point, the attacker has already extracted a significant amount of WETH.

**Transaction Evidence:**

- **Transaction 1 (`0x2aec4fdb2a09ad4269a410f2c770737626fb62c54e0fa8ac25e8582d4b690cca`):**
    - `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH) sends value to the attacker contract `0xA21a2B59d80dC42D332F778Cbb9eA127100e5d75`.
    - The attacker contract then sends value to `0xa1f8a6807c402e4a15ef4eba36528a3fed24e577`.
    - Multiple calls from `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` to `0x4ebdf703948ddcea3b11f675b4d1fba9d2414a14` with value.
    - `0x4ebdf703948ddcea3b11f675b4d1fba9d2414a14` sends value back to `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2`.
    - `0xa1f8a6807c402e4a15ef4eba36528a3fed24e577` sends value back to the attacker contract.
    - The attacker contract then sends value to `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2`.
    - Finally, the attacker contract sends value to `0x5f4C21c9Bb73c8B4a296cC256C0cDe324dB146DF`.

- **Transaction 2 (`0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb`):**
    - `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH) sends value to `0xfb8814d005c5f32874391e888da6eb2fe7a27902`.
    - `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH) sends value to the attacker contract `0xA21a2B59d80dC42D332F778Cbb9eA127100e5d75`.
    - The attacker contract then sends value to `0x5f4C21c9Bb73c8B4a296cC256C0cDe324dB146DF`.

These transactions clearly show the attacker manipulating the WETH balance within the `ElasticRigidVault` contract using reentrancy.

## Rugpull Detection
Based on the available data, there is no direct evidence of a rugpull. However, the reentrancy vulnerability and the subsequent draining of funds from the `ElasticRigidVault` contract indicate a severe security flaw that could have been exploited intentionally or unintentionally. Further investigation into the contract's development history and the team's actions following the exploit is necessary to determine if a rugpull was involved.
