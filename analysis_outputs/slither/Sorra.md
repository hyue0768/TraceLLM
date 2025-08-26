# Sorra - Security Analysis (Trace + Slither)

# Security Incident Analysis Report

## Attack Overview
The attack appears to be an exploit of the `SorraStaking` contract (`0x5d16b8Ba2a9a4ECA6126635a6FFbF05b52727d50`) leveraging a reentrancy vulnerability in the `withdraw` function. The attacker exploited the reentrancy to repeatedly claim rewards before the state could be updated, effectively draining the contract's reward pool.

## Contract Identification
- Attacker Contract: `0xdc8076c21365a93aaC0850B67e4cA5fDeC5FAb9b`
    - This contract initiates the attack by deploying a malicious contract and calling functions on the victim contract.
- Victim Contract: `0x5d16b8Ba2a9a4ECA6126635a6FFbF05b52727d50` (SorraStaking)
    - This contract is identified as the victim because the attacker interacts with its `claim` and `deposit` functions, and the Slither analysis highlights a reentrancy vulnerability in its `withdraw` function. The attacker's actions result in a loss of funds from this contract.
- Helper Contracts:
    - `0xB575b2599B9dCf242BB9dCA60DC2aD36a1cA8CD7` - Contract created by the attacker in transaction `0x1e83b95a9f946a03bcc6ce2887434c2979e0f3adcb6f44f205751c14c5b27bda`. This contract is likely used to perform the reentrancy attack.

## Vulnerability Analysis
The `SorraStaking` contract has a reentrancy vulnerability in the `withdraw` function, as identified by Slither:

```solidity
function withdraw(uint256 _amount) external nonReentrant {
        require(depositingEnabled, "Depositing is not enabled");
        require(_amount > 0, "Amount must be greater than 0");
        Position storage position = userPositions[_msgSender()];
        require(position.totalAmount >= _amount, "Insufficient funds");
        require(position.deposits.length > 0, "No deposits found");

        Deposit storage dep = position.deposits[0];
        require(block.timestamp > dep.depositTime + vestingTiers[dep.tier].period, "Vesting period not over");

        uint256 rewardAmount = _calculateRewards(_amount, _msgSender());

        // Update position before transferring tokens to prevent reentrancy attacks
        _updatePosition(_msgSender(),_amount,true,position.deposits[0].tier);

        // Transfer reward tokens to user
        SafeERC20.safeTransfer(rewardToken, _msgSender(), rewardAmount);

        // Update total rewards distributed
        totalRewardsDistributed += rewardAmount;
        userRewardsDistributed[_msgSender()] += rewardAmount;
    }

function _updatePosition(address account, uint256 amount, bool isWithdraw, uint8 tier) internal {
        vaultExtension.setShare(account,amount,isWithdraw);
        if(isWithdraw){
            _decreasePosition(account,amount);
        } else {
            _increasePosition(account,amount,tier);
        }
    }
```

The vulnerability lies in the fact that `vaultExtension.setShare` is called *before* the internal accounting of the `SorraStaking` contract is updated. This external call allows the attacker to re-enter the `withdraw` function before the state variables `totalRewardsDistributed` and `userRewardsDistributed[_msgSender()]` are updated.

## Exploitation Mechanism
1. **Contract Creation:** The attacker deploys a contract `0xB575b2599B9dCf242BB9dCA60DC2aD36a1cA8CD7` (Tx: `0x1e83b95a9f946a03bcc6ce2887434c2979e0f3adcb6f44f205751c14c5b27bda`). This contract likely contains the malicious logic to exploit the reentrancy vulnerability.
2. **Set Implementation:** The attacker calls `setImpl` on contract `0xFa39257C629F9A5DA2c0559deBe2011eEF7C1E9f` (Tx: `0x285d2eb16278d86085df6b9f192b5fc39b8f66e4d36304b1d24c6bfc189a3701`). The purpose of this transaction is unclear without the contract code.
3. **Claim Rewards (Reentrancy):** The attacker calls the `claim` function on contract `0xFa39257C629F9A5DA2c0559deBe2011eEF7C1E9f` multiple times (Tx: `0x6439d63cc57fb68a32ea8ffd8f02496e8abad67292be94904c0b47a4d14ce90d`, `0x03ddae63fc15519b09d716b038b2685f4c64078c5ea0aa71c16828a089e907fd`, `0xf1a494239af59cd4c1d649a1510f0beab8bb78c62f31e390ba161eb2c29fbf8b`, `0x09b26b87a91c7aea3db05cfcf3718c827eba58c0da1f2bf481505e0c8dc0766b`). These transactions likely trigger the reentrancy vulnerability in the `withdraw` function. The attacker's contract re-enters the `withdraw` function during the `vaultExtension.setShare` call, allowing it to claim rewards multiple times before the initial withdrawal is fully processed.
4. **Deposit:** The attacker calls the `deposit` function on contract `0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b` (Tx: `0x768a6983ed719e07eeb5e2a52501125b3554ec583c8d553a09b72339e3bc74fd`, `0x6ee3b7864c032c8c9c97cb088f620396144345087f4771d35ef68612466aea57`). The purpose of this transaction is unclear without the contract code.
5. **MetaRoute:** The attacker calls the `metaRoute` function on contract `0xf621Fb08BBE51aF70e7E0F4EA63496894166Ff7F` (Tx: `0x0fcddf2e1a78d7eff65d7eeca567b1273e8ac4d8c829cbeb9682135c1625f8cb`). This transaction likely transfers the stolen funds to the attacker's desired destination.

The trace data shows that the attacker interacts with Uniswap V2 Router (`0x7a250d5630b4cf539739df2c5dacb4c659f2488d`) multiple times during the `claim` calls, suggesting that the attacker is swapping the claimed rewards for other tokens. The value transfers to the attacker's address in the traces confirm that the attacker is receiving the claimed rewards.
