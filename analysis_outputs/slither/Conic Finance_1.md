# Conic Finance_1 - Security Analysis (Trace + Slither)

# Security Incident Analysis Report

## Attack Overview
The incident appears to be an exploit targeting the Conic Finance protocol, specifically the `ConicPoolV2` contract. The attacker exploits a reentrancy vulnerability in conjunction with the `RewardManagerV2` contract to manipulate reward claiming and token swapping, ultimately draining funds from the pool.

## Contract Identification
- Attacker Contract: `0x486cb3f61771Ed5483691dd65f4186DA9e37c68e`
    - This contract initiates the attack by calling the `approve` function, likely to authorize the transfer of tokens from the victim contract to the attacker-controlled address. It also receives the exploited funds.
- Victim Contract: `0x369cBC5C6f139B1132D3B91B87241B37Fc5B971f` (ConicPoolV2)
    - The transaction traces show that the attacker interacts with this contract, and the slither analysis reveals several reentrancy vulnerabilities within the `ConicPoolV2` and `RewardManagerV2` contracts. The funds are ultimately drained from this contract.
- Helper Contracts: None apparent from the provided data.

## Vulnerability Analysis
The primary vulnerability lies in the interaction between `ConicPoolV2` and `RewardManagerV2`, specifically involving reentrancy during reward claiming and token swapping.

Slither identified several reentrancy vulnerabilities, including:

- **Reentrancy in `RewardManagerV2._accountCheckpoint(address)`:** This function calls `poolCheckpoint()`, which makes external calls to claim rewards and swap tokens. State variables are written *after* these calls, creating a reentrancy opportunity.
- **Reentrancy in `RewardManagerV2.claimEarnings()`:** This function calls `_accountCheckpoint()` and `_claimPoolEarningsAndSellRewardTokens()`, both of which make external calls. State variables are written *after* these calls.
- **Reentrancy in `ConicPoolV2.depositFor(address,uint256,uint256,bool)`:** This function calls `underlying.safeTransferFrom` and `_depositToCurve`, which makes external delegatecalls. State variables are written *after* these calls.
- **Reentrancy in `ConicPoolV2.unstakeAndWithdraw(uint256,uint256)`:** This function calls `controller.lpTokenStaker().unstakeFrom` and `withdraw`, which makes external delegatecalls. State variables are written *after* these calls.
- **Reentrancy in `ConicPoolV2.withdraw(uint256,uint256)`:** This function calls `_withdrawFromCurve`, which makes external delegatecalls. State variables are written *after* these calls.

A particularly relevant vulnerability is the "arbitrary from in transferFrom" issue flagged by Slither in the `RewardManagerV2` contract:

```solidity
RewardManagerV2.poolCheckpoint() (RewardManagerV2.sol#80-129) uses arbitrary from in transferFrom: CRV.safeTransferFrom(pool,address(this),crvFee) (RewardManagerV2.sol#120)
RewardManagerV2.poolCheckpoint() (RewardManagerV2.sol#80-129) uses arbitrary from in transferFrom: CVX.safeTransferFrom(pool,address(this),cvxFee) (RewardManagerV2.sol#121)
RewardManagerV2.claimEarnings() (RewardManagerV2.sol#204-236) uses arbitrary from in transferFrom: CNC.safeTransferFrom(pool,msg.sender,cncAmount) (RewardManagerV2.sol#223)
RewardManagerV2.claimEarnings() (RewardManagerV2.sol#204-236) uses arbitrary from in transferFrom: CRV.safeTransferFrom(pool,msg.sender,crvAmount) (RewardManagerV2.sol#221)
RewardManagerV2.claimEarnings() (RewardManagerV2.sol#204-236) uses arbitrary from in transferFrom: CVX.safeTransferFrom(pool,msg.sender,cvxAmount) (RewardManagerV2.sol#222)
```

This allows the attacker to potentially transfer tokens from the pool to themselves without proper authorization.

## Exploitation Mechanism
Based on the transaction traces and vulnerability analysis, the exploit likely unfolded as follows:

1. **Approval:** The attacker first calls `approve()` on an ERC20 token contract, authorizing their contract (`0x486cb3f61771Ed5483691dd65f4186DA9e37c68e`) to spend tokens on behalf of the caller (`0xB6369F59fc24117B16742c9dfe064894d03B3B80`). This is evidenced by transaction `0xc8603387e50e659d128790b827627911b039e986f221eda9124f1e263f2093a0`.
2. **Reentrancy Trigger:** The attacker calls a function in `ConicPoolV2` (likely `withdraw` or `unstakeAndWithdraw`) that eventually leads to a call to `RewardManagerV2.claimEarnings()` or `RewardManagerV2._accountCheckpoint()`.
3. **Reentrant Call:** Within `claimEarnings` or `_accountCheckpoint`, the external call to `controller.lpTokenStaker().claimCNCRewardsForPool(pool)` or similar triggers a reentrancy back into the `ConicPoolV2` contract.
4. **Exploitation:** During the reentrant call, the attacker leverages the "arbitrary from in transferFrom" vulnerability in `RewardManagerV2` to transfer tokens from the pool to their own contract. Alternatively, the attacker could manipulate the reward claiming logic or token swapping mechanisms due to the state being updated *after* the external calls.
5. **Drain Funds:** The attacker repeats steps 3 and 4 to drain a significant amount of tokens from the `ConicPoolV2` contract. This is evidenced by the large value transfer in transaction `0x37acd17a80a5f95728459bfea85cb2e1f64b4c75cf4a4c8dcb61964e26860882` from `0x7f86bf177dd4f3494b841a37e810a34dd56c829b` to the attacker contract.
6. **Cleanup:** The attacker might make a final call to `ConicPoolV2` to finalize the exploit and potentially cover their tracks. This is evidenced by transaction `0x8478a9567b06d5b9a2e09a0599a95c674cf2d9a70496e6ef7e5f0f3d0ec9a0ef`.

The key to this exploit is the reentrancy vulnerability combined with the ability to manipulate token transfers or reward claiming logic within the reentrant context. The `approve()` call is a standard prerequisite for ERC20 token transfers, and the subsequent calls exploit the vulnerable functions in `ConicPoolV2` and `RewardManagerV2`.

## Rugpull Detection
Based on the provided data, there is no direct evidence of a rugpull. However, the presence of reentrancy vulnerabilities, the "arbitrary from in transferFrom" issue, and the lack of proper state management during external calls raise concerns about the security of the Conic Finance protocol. A more thorough investigation of the contract ownership, deployment history, and privileged functions would be necessary to definitively rule out a rugpull.
