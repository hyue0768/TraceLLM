# Conic Finance_2 - Security Analysis (Trace + Slither)

# Security Incident Analysis Report

## Attack Overview
This report analyzes a potential exploit of the Conic Finance protocol, specifically targeting the `ConicEthPool` contract. The analysis suggests a possible manipulation of reward claiming through reentrancy in the `RewardManagerV2` contract, potentially leading to unauthorized fund withdrawals.

## Contract Identification
- Attacker Contract: `0x743599BA5CfA3cE8c59691aF5ef279AaaFA2E4EB`
    - This contract receives a large amount of WETH (20000000000000000000000 wei) from the `c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH contract). It then interacts extensively with the `ConicEthPool` and `RewardManagerV2` contracts, suggesting its role as an exploiter.
- Victim Contract: `0xbb787d6243a8d450659e09ea6fd82f1c859691e9` (ConicEthPool)
    - The transaction trace shows numerous calls to this contract, including deposits, withdrawals, and internal function calls. The `RewardManagerV2` contract, which is closely associated with this contract, also exhibits reentrancy vulnerabilities.
- Helper Contracts:
    - `0x5fae7e604fc3e24fd43a72867cebac94c65b404a`
    - `0x0f3159811670c117c372428d4e69ac32325e4d0f`
    - These contracts are called by the WETH contract and then call the attacker contract.

## Vulnerability Analysis
The `RewardManagerV2` contract has several reentrancy vulnerabilities, particularly in the `claimEarnings()` and `_accountCheckpoint()` functions. The Slither report highlights these vulnerabilities:

```solidity
Reentrancy in RewardManagerV2.claimEarnings() (RewardManagerV2.sol#203-235):
	External calls:
	- _accountCheckpoint(msg.sender) (RewardManagerV2.sol#204)
		- returndata = address(token).functionCall(data,SafeERC20: low-level call failed) (SafeERC20.sol#110)
		- controller.lpTokenStaker().claimCNCRewardsForPool(pool) (RewardManagerV2.sol#262)
		- (success,returndata) = target.call{value: value}(data) (Address.sol#135)
		- CNC_ETH_POOL.exchange(0,1,wethBalance_,_minAmountOut(address(WETH),address(CNC),wethBalance_),false,pool) (RewardManagerV2.sol#436-443)
		- IConvexHandler(convexHandler).claimBatchEarnings(IConicPool(pool).allCurvePools(),pool) (RewardManagerV2.sol#270)
		- curvePool_.exchange(from_,to_,tokenBalance_,_minAmountOut(address(rewardToken_),address(WETH),tokenBalance_),false,address(this)) (RewardManagerV2.sol#410-417)
		- SUSHISWAP.swapExactTokensForTokens(tokenBalance_,_minAmountOut(address(rewardToken_),address(WETH),tokenBalance_),path_,address(this),block.timestamp) (RewardManagerV2.sol#424-430)
		- CRV.safeTransferFrom(pool,address(this),crvFee) (RewardManagerV2.sol#119)
		- CVX.safeTransferFrom(pool,address(this),cvxFee) (RewardManagerV2.sol#120)
		- CRV.safeApprove(address(locker),crvFee) (RewardManagerV2.sol#123)
		- CVX.safeApprove(address(locker),cvxFee) (RewardManagerV2.sol#124)
		- locker.receiveFees(crvFee,cvxFee) (RewardManagerV2.sol#125)
	- _claimPoolEarningsAndSellRewardTokens() (RewardManagerV2.sol#214)
		- controller.lpTokenStaker().claimCNCRewardsForPool(pool) (RewardManagerV2.sol#262)
		- CNC_ETH_POOL.exchange(0,1,wethBalance_,_minAmountOut(address(WETH),address(CNC),wethBalance_),false,pool) (RewardManagerV2.sol#436-443)
		- IConvexHandler(convexHandler).claimBatchEarnings(IConicPool(pool).allCurvePools(),pool) (RewardManagerV2.sol#270)
		- curvePool_.exchange(from_,to_,tokenBalance_,_minAmountOut(address(rewardToken_),address(WETH),tokenBalance_),false,address(this)) (RewardManagerV2.sol#410-417)
		- SUSHISWAP.swapExactTokensForTokens(tokenBalance_,_minAmountOut(address(rewardToken_),address(WETH),tokenBalance_),path_,address(this),block.timestamp) (RewardManagerV2.sol#424-430)
	External calls sending eth:
	- _accountCheckpoint(msg.sender) (RewardManagerV2.sol#204)
		- (success,returndata) = target.call{value: value}(data) (Address.sol#135)
```

The `_accountCheckpoint` function calls `poolCheckpoint()`, which in turn makes external calls to claim rewards. The state is updated *after* these external calls, creating a classic reentrancy scenario. An attacker could re-enter `claimEarnings()` during the external call in `_accountCheckpoint()`, manipulating the reward calculation and potentially draining funds.

## Exploitation Mechanism
1. **Initial Deposit:** The attacker likely deposited a small amount of liquidity into the `ConicEthPool` to become eligible for rewards.
2. **Trigger Reward Claim:** The attacker calls `claimEarnings()` on the `RewardManagerV2` contract.
3. **Reentrancy:**
    - `claimEarnings()` calls `_accountCheckpoint()`.
    - `_accountCheckpoint()` calls `poolCheckpoint()`.
    - `poolCheckpoint()` makes an external call to claim rewards from Curve/Convex.
    - During this external call, the attacker's contract re-enters `claimEarnings()`.
    - The attacker can manipulate the state within the re-entered `claimEarnings()` call, potentially increasing their reward allocation.
4. **Repeat Reentrancy:** The attacker repeats the reentrancy process multiple times to maximize their reward allocation.
5. **Withdrawal:** After manipulating the reward system, the attacker withdraws a disproportionately large amount of funds from the `ConicEthPool`.

**Transaction Evidence:**
The transaction trace shows the attacker contract receiving a large amount of WETH and then making numerous calls to the ConicEthPool and RewardManagerV2 contracts. The high gas usage and multiple nested calls suggest a complex interaction, potentially involving reentrancy.

**Rugpull Detection:**
Based on the provided data, there is no clear evidence of a rugpull. The attacker is using a reentrancy vulnerability to manipulate the reward system, rather than exploiting privileged functions or directly draining funds as a contract owner. However, further investigation is needed to rule out any hidden backdoors or malicious code within the contracts.
