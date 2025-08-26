# Mirage Finance - Security Analysis (Trace + Mythril)

# Security Incident Analysis Report

## Attack Overview
This report analyzes a likely rugpull attack targeting a token contract. The attacker appears to have exploited a vulnerability related to integer underflow within the token contract to manipulate balances, ultimately draining liquidity.

## Contract Identification
- Attacker Contract: `0x4843E00Ef4c9f9f6e6aE8d7b0A787f1C60050b01`
    - This contract initiated the transaction and received a large transfer of tokens at the end of the trace, strongly suggesting it's the attacker's contract.
- Victim Contract: `0x0d99f24e96c42432a758124496f4ce9c67f6aa7b`
    - This contract is identified as the victim based on the transaction trace and the Mythril analysis. The trace shows a transfer of value to this contract from Uniswap (`0x7a250d5630b4cf539739df2c5dacb4c659f2488d`), and then a subsequent transfer of value *from* this contract to another contract (`0x3f5a63b89773986fd436a65884fcd321de77b832`). The Mythril analysis also flags this contract as having a high severity integer underflow vulnerability.
- Helper Contracts:
    - `0x7a250d5630b4cf539739df2c5dacb4c659f2488d`: Uniswap V2 Router
    - `0x3f5a63b89773986fd436a65884fcd321de77b832`: Unknown contract.

## Vulnerability Analysis
The Mythril analysis identifies a high severity integer underflow vulnerability in the victim contract `0x0d99f24e96c42432a758124496f4ce9c67f6aa7b`. The vulnerability is located within the `name()` function and potentially within a function called `link_classic_internal(uint64,int64)`.

While the exact code of the vulnerable function isn't provided, the Mythril report indicates that an arithmetic operation within these functions can underflow. This means that subtracting a large number from a smaller number can result in a very large positive number, potentially leading to unintended behavior and allowing the attacker to manipulate balances.

## Exploitation Mechanism
The exploitation likely proceeded as follows:

1. **Initial Setup:** The attacker likely deposited funds into the WETH/VictimToken liquidity pool on Uniswap.
2. **Vulnerability Trigger:** The attacker interacted with the victim contract `0x0d99f24e96c42432a758124496f4ce9c67f6aa7b`, triggering the integer underflow vulnerability in either the `name()` or `link_classic_internal()` function. This likely involved calling a function that manipulated internal balances or mappings within the contract.
3. **Balance Manipulation:** The integer underflow allowed the attacker to artificially inflate their balance within the victim contract.
4. **Liquidity Drain:** The attacker then used the inflated balance to withdraw a disproportionately large amount of WETH from the Uniswap pool via the Uniswap Router (`0x7a250d5630b4cf539739df2c5dacb4c659f2488d`). This is evidenced by the transfer of `38395718675614414` wei from WETH contract (`0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2`) to Uniswap Router.
5. **Token Transfer:** The attacker then transferred the tokens received from Uniswap (`6360026517476820709` wei) to their own contract (`0x4843E00Ef4c9f9f6e6aE8d7b0A787f1C60050b01`).

**Evidence from Transaction Trace:**

*   **Call 1:** `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH) -> `0x7a250d5630b4cf539739df2c5dacb4c659f2488d` (Uniswap Router): This indicates a transfer of WETH to the Uniswap Router, likely as part of a swap or liquidity removal.
*   **Call 2:** `0x7a250d5630b4cf539739df2c5dacb4c659f2488d` (Uniswap Router) -> `0x0d99f24e96c42432a758124496f4ce9c67f6aa7b` (Victim): This suggests that the Uniswap Router is interacting with the victim contract. This is likely where the attacker is using the inflated balance to withdraw liquidity.
*   **Call 4:** `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH) -> `0x564677e09b0ab80feed1ee6b02c44ade3ee92ddb` (Unknown): This is a transfer of WETH to an unknown contract.
*   **Call 5:** `0x564677e09b0ab80feed1ee6b02c44ade3ee92ddb` (Unknown) -> `0x4843E00Ef4c9f9f6e6aE8d7b0A787f1C60050b01` (Attacker): This is the final transfer of WETH to the attacker's contract.

**Rugpull Indicators:**

*   **Integer Underflow Vulnerability:** The presence of a high severity integer underflow vulnerability in the victim contract is a strong indicator of a potential rugpull.
*   **Liquidity Drain:** The attacker drained a significant amount of WETH from the Uniswap pool.
*   **Token Transfer to Attacker:** The attacker consolidated the stolen funds in their own contract.

Based on the evidence, this incident is highly likely a rugpull attack exploiting an integer underflow vulnerability in the victim contract. The attacker manipulated balances to drain liquidity from a Uniswap pool.
