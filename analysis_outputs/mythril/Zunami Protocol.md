# Zunami Protocol - Security Analysis (Trace + Mythril)

# Security Incident Analysis Report

## Attack Overview
This report analyzes a potential rugpull attack involving a token contract and subsequent draining of liquidity. The analysis focuses on identifying the victim contract, the exploitation pattern, and the reconstruction of the attack sequence based on the provided transaction results and Mythril analysis.

## Contract Identification
- Attacker Contract: `0xA21a2B59d80dC42D332F778Cbb9eA127100e5d75`
    - This contract appears to be controlled by the attacker and is used to receive and forward funds. The traces show that this contract receives tokens from various sources and then transfers them to other addresses, including the attacker's externally owned account (EOA).
- Victim Contract: `0xb40b6608b2743e691c9b54ddbdee7bf03cd79f1c`
    - The Mythril analysis identifies this contract as having multiple high-severity integer arithmetic vulnerabilities (SWC-101). These vulnerabilities exist in core functions like `totalSupply()`, `balanceOf(address)`, `allowance(address,address)`, `increaseAllowance(address,uint256)`, and internal functions. The presence of these vulnerabilities in a token contract strongly suggests that this is the victim contract.
- Helper Contracts:
    - `0xa1f8a6807c402e4a15ef4eba36528a3fed24e577`: This contract receives a large transfer of tokens from the victim contract via the attacker contract in transaction `0x2aec4fdb2a09ad4269a410f2c770737626fb62c54e0fa8ac25e8582d4b690cca`. Its purpose is not immediately clear, but it acts as an intermediary in the transfer of funds.
    - `0x4ebdf703948ddcea3b11f675b4d1fba9d2414a14`: This contract receives multiple transfers of ETH from WETH (`0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2`) and then sends ETH back to WETH. This suggests it is a swapping contract or a contract involved in providing liquidity.
    - `0xfb8814d005c5f32874391e888da6eb2fe7a27902`: This contract receives a small amount of WETH from WETH in transaction `0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb`. Its purpose is not immediately clear.

## Vulnerability Analysis
The Mythril analysis highlights multiple integer overflow/underflow vulnerabilities (SWC-101) in the victim contract `0xb40b6608b2743e691c9b54ddbdee7bf03cd79f1c`. While the exact code is not provided, the vulnerable functions are:

- `totalSupply()`: An integer underflow in this function could lead to a manipulated total supply value, affecting token price and calculations.
- `balanceOf(address)`: An integer underflow in this function could allow an attacker to manipulate their balance, potentially allowing them to transfer more tokens than they actually own.
- `allowance(address,address)`: An integer underflow in this function could allow an attacker to manipulate the allowance granted to them, potentially allowing them to transfer more tokens than intended.
- `increaseAllowance(address,uint256)`: An integer underflow in this function could allow an attacker to set a very large allowance, potentially allowing them to drain tokens.

The vulnerability in `increaseAllowance` is particularly concerning, as the Mythril report shows a transaction attempting to set the allowance to `ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`, which is the maximum uint256 value. This suggests an attempt to exploit a potential integer overflow/underflow in the allowance mechanism.

## Exploitation Mechanism
Based on the transaction traces and Mythril analysis, the following exploitation mechanism is likely:

1. **Vulnerability Exploitation:** The attacker exploits one of the integer overflow/underflow vulnerabilities in the victim contract `0xb40b6608b2743e691c9b54ddbdee7bf03cd79f1c`. The `increaseAllowance` function seems to be the primary target, potentially allowing the attacker to manipulate the allowance granted to their contract `0xA21a2B59d80dC42D332F778Cbb9eA127100e5d75`.
2. **Token Transfer:** Once the attacker has inflated their allowance, they transfer a large amount of tokens from the victim contract to their contract `0xA21a2B59d80dC42D332F778Cbb9eA127100e5d75`. This is evidenced by the trace of transaction `0x2aec4fdb2a09ad4269a410f2c770737626fb62c54e0fa8ac25e8582d4b690cca`, where `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH) sends 300 WETH to the attacker contract, which then sends 300 WETH to `0xa1f8a6807c402e4a15ef4eba36528a3fed24e577`.
3. **Liquidity Drain:** The attacker then uses the acquired tokens to drain liquidity from various pools. The trace of transaction `0x2aec4fdb2a09ad4269a410f2c770737626fb62c54e0fa8ac25e8582d4b690cca` shows multiple calls from WETH to `0x4ebdf703948ddcea3b11f675b4d1fba9d2414a14` with varying amounts of ETH, suggesting the attacker is swapping the tokens for ETH.
4. **Final Transfer:** Finally, the attacker transfers the ETH to their EOA or another address they control. This is evidenced by the trace of transaction `0x2aec4fdb2a09ad4269a410f2c770737626fb62c54e0fa8ac25e8582d4b690cca`, where `0xa1f8a6807c402e4a15ef4eba36528a3fed24e577` sends a large amount of tokens back to the attacker contract, which then sends a smaller amount to the original sender `0x5f4C21c9Bb73c8B4a296cC256C0cDe324dB146DF`.

**Rugpull Detection:**

Based on the analysis, the following signs suggest a potential rugpull:

- **Integer Overflow/Underflow Vulnerabilities:** The presence of high-severity integer overflow/underflow vulnerabilities in a token contract is a significant red flag.
- **Suspicious `increaseAllowance` Call:** The attempt to set the allowance to the maximum uint256 value suggests a deliberate attempt to exploit the allowance mechanism.
- **Liquidity Drain:** The multiple calls from WETH to `0x4ebdf703948ddcea3b11f675b4d1fba9d2414a14` suggest the attacker is swapping the tokens for ETH, effectively draining liquidity.
- **Final Transfer to Attacker:** The final transfer of ETH to the attacker's EOA confirms that the attacker profited from the exploitation.

## Conclusion
The provided data strongly suggests a rugpull attack. The attacker exploited integer overflow/underflow vulnerabilities in the victim token contract `0xb40b6608b2743e691c9b54ddbdee7bf03cd79f1c` to manipulate their allowance, transfer tokens, and drain liquidity from various pools, ultimately profiting from the attack.
