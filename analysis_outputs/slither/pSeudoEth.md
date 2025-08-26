# pSeudoEth - Security Analysis (Trace + Slither)

# Security Incident Analysis Report

## Attack Overview
The provided data suggests a potential front-running attack targeting a UniswapV2Pair contract. The attacker monitors transactions and exploits the predictable nature of `block.timestamp` in the `_update` function to manipulate the price feed and gain an advantage in subsequent trades.

## Contract Identification
- Attacker Contract: `0xf88D1D6D9DB9A39Dbbfc4B101CECc495bB0636F8` - This is the contract initiating the transactions and receiving the profits.
- Victim Contract: `0x2033B54B6789a963A02BfCbd40A46816770f1161` - This is a UniswapV2Pair contract. The Slither analysis highlights several vulnerabilities, including a weak PRNG and reentrancy issues. The front-running attack leverages the weak PRNG.
- Helper Contracts: `0xea75AeC151f968b8De3789CA201a2a3a7FaeEFbA` - This is the contract that calls the attacker contract.

## Vulnerability Analysis
The primary vulnerability lies in the `_update` function of the `UniswapV2Pair` contract, specifically the use of `block.timestamp` to calculate `blockTimestampLast`.

```solidity
function _update(uint balance0, uint balance1, uint112 _reserve0, uint112 _reserve1) private {
    require(balance0 <= uint256(uint112(-1)) && balance1 <= uint256(uint112(-1)), 'UniswapV2: OVERFLOW');
    uint32 blockTimestamp = uint32(block.timestamp % 2 ** 32);
    uint32 timeElapsed = blockTimestamp - blockTimestampLast; // overflow is desired
    if (timeElapsed > 0 && _reserve0 != 0 && _reserve1 != 0) {
        price0CumulativeLast += uint256(UQ112x112.encode(_reserve1).uqdiv(_reserve0)) * timeElapsed;
        price1CumulativeLast += uint256(UQ112x112.encode(_reserve0).uqdiv(_reserve1)) * timeElapsed;
    }
    reserve0 = uint112(balance0);
    reserve1 = uint112(balance1);
    blockTimestampLast = blockTimestamp;
    emit Sync(reserve0, reserve1);
}
```

Slither identifies this as a "weak PRNG" because `block.timestamp` is easily predictable and manipulatable by miners. The attacker can influence the `timeElapsed` value, which directly affects the `price0CumulativeLast` and `price1CumulativeLast` variables.

## Exploitation Mechanism

1. **Monitoring:** The attacker contract `0xf88D1D6D9DB9A39Dbbfc4B101CECc495bB0636F8` monitors the mempool for transactions involving the `UniswapV2Pair` contract `0x2033B54B6789a963A02BfCbd40A46816770f1161`.
2. **Front-Running:** When a target transaction is detected, the attacker submits a transaction with a higher gas price to ensure it is executed before the target transaction.
3. **Timestamp Manipulation:** The attacker's transaction calls a function (likely `swap` or a custom function that triggers `_update`) in the `UniswapV2Pair` contract. By carefully timing the transaction, the attacker can influence the `block.timestamp` and, consequently, the `timeElapsed` value in the `_update` function. This artificially inflates or deflates the `price0CumulativeLast` and `price1CumulativeLast` variables.
4. **Profitable Trade:** After manipulating the price feed, the attacker executes a trade that benefits from the skewed prices. This could involve buying tokens at a lower price or selling them at a higher price than the "true" market value.
5. **Repeat:** The attacker repeats this process to continuously profit from the manipulated price feed.

**Transaction Evidence:**

- Transactions with hash `0x36a989721703704a0dfff9b247c30eeaa15c4c3f934e5027d07890baa830ca1f`, `0x7edfabdc7e96b862277d2365f8fa7d84a0a14d4811ee48485407b9198a86da86`, and `0x4ab68b21799828a57ea99c1288036889b39bf85785240576e697ebff524b3930` all call the attacker contract with the same input `0x878830fa`. This suggests a function call to the attacker contract that triggers the exploit. The high gas used in these transactions further supports the complexity of the attack.
- Transaction `0x024dd395529d4b9e89fa5b8a7a7b0d5f8501657d31f4f4c0689141081beabb3d` shows a series of calls between `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH), `0x7a250d5630b4cf539739df2c5dacb4c659f2488d` (UniswapV2 Router), and `0x67cd91b7b5f2bd1f95a0a9629d7de2c5d66edeeb`. This likely represents the attacker's profitable trade after manipulating the price feed.

**Rugpull Detection:**

Based on the provided data, there is no direct evidence of a rugpull. However, the attacker's ability to manipulate the price feed raises serious concerns about the integrity of the UniswapV2Pair contract. If the attacker is also the owner or has privileged access to the contract, they could potentially drain the liquidity pool after manipulating the price feed to their advantage. This would effectively be a rugpull. Further investigation is needed to determine if the attacker has any privileged control over the victim contract.
