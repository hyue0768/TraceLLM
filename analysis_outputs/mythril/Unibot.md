# Unibot - Security Analysis (Trace + Mythril)

# Security Incident Analysis Report

## Attack Overview
This report analyzes a complex attack involving contract creation, function calls, and token transfers. The primary vulnerability appears to be an integer underflow in the `balanceOf` function of contract `0x2b326A17B5Ef826Fa4e17D3836364ae1F0231a6f`. The attacker, `0x413e4Fb75c300B92fEc12D7c44e4c0b4FAAB4d04`, leverages this vulnerability, potentially in conjunction with other contracts, to manipulate balances and potentially drain assets. The attack does not appear to be a simple rugpull, but a more sophisticated exploit.

## Contract Identification
- Attacker Contract: `0x413e4Fb75c300B92fEc12D7c44e4c0b4FAAB4d04`
    - This address initiates numerous contract creations and function calls, indicating its role as the attacker's primary control point. It also receives initial funding.
- Victim Contract: `0x2b326A17B5Ef826Fa4e17D3836364ae1F0231a6f`
    - This contract is created by the attacker in transaction `0x86f0f4d5fc8871fffc6c697b459476a30d601f1d860050b1fe8a12cd3a47fedf`. Multiple subsequent transactions call this contract with input `0x5456a7bf`, and the Mythril report identifies an integer underflow vulnerability in the `balanceOf` function. This strongly suggests this contract is the primary target.
- Helper Contracts: Several contracts are created by the attacker, including `0x6b931f5c725b6442144051545444f95d07F66632` (created in transaction `0x5534536519c664bb18c90a1bd574195e80c07a395bf5962ddcf14f22ffa1a26a`) and `0x9838d25126514981C1fBe2Ac1B8b13eBE6781a47` (created in transaction `0xdaef668fd35814591e7e54157cdef79537637fa2544766eaead90180800c3922`). These contracts are likely used to facilitate the exploit.

## Vulnerability Analysis
The Mythril analysis identifies a high-severity integer arithmetic bug (SWC-101) in the `balanceOf(address)` function of contract `0x2b326A17B5Ef826Fa4e17D3836364ae1F0231a6f`. The analysis states:

"The arithmetic operator can underflow. It is possible to cause an integer overflow or underflow in the arithmetic operation."

While the exact code of the `balanceOf` function is not provided, the vulnerability suggests that the function may not properly handle cases where a subtraction operation results in a negative value, leading to an underflow. This can potentially allow an attacker to manipulate the reported balance of an address.

## Exploitation Mechanism
The exploitation mechanism appears to involve the following steps:

1. **Contract Creation:** The attacker deploys several contracts, including the victim contract `0x2b326A17B5Ef826Fa4e17D3836364ae1F0231a6f` and helper contracts.
2. **Initial Funding:** The attacker receives initial funding of 0.5 ETH (transactions `0x13fa3ef7f6a375b2230dcf3c7b49ffb428ec1c83c8a0827022bc254df8678fe0` and `0x7ac54df24697f0ff93822a088cbc53b6cdd050f4bd5e602cc1d0389588ac59ff`).
3. **Vulnerability Trigger:** The attacker repeatedly calls the victim contract `0x2b326A17B5Ef826Fa4e17D3836364ae1F0231a6f` with the input `0x5456a7bf`. While the function corresponding to this input is unknown without the contract source code, the Mythril report suggests that these calls are related to the `balanceOf` function and are likely designed to trigger the integer underflow vulnerability.
4. **Interaction with other protocols:** The attacker interacts with `0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD` using the `execute` function. This is likely a proxy or multi-sig contract, and the attacker is using it to perform actions on behalf of another address. The transactions involving this contract are `0x7f7e8b5b599ed73d63fe17157fdc3f16d173937ce19f60d2125c7d5f3441dbef`, `0x74d245b1026afcff2f724c00f117102c14daa935aede4bc382eedeb3372968db`, `0xfb579f319b00be054e01073dbd893bdc91ba6247029966f00f9faea465842bb1`, `0x63cde5379e440e5ac0e25e32936721a9476f082734787f49ca2b29b01eaeb774`, etc.
5. **Token Deposits:** The attacker deposits tokens into contract `0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b` using the `deposit` function. This contract is likely a vault or staking contract. The transactions are `0x30508db6cffcfd6572b7d3aa6f081567bf33e829b4304df1900261754622e308`, `0xa32fec4d84f1f6cedbec9dcacc6185895062cb303092c678d59522f050e93c53`, `0x2aca9af0a35a88bd16ee61048c46b0e29eefb16e1aaf0cac0a71a60f8b6f8b9e`, `0x27852b14be26e810edbe855c91eeaed2b3ea45d637ed69c674662d7c8e6ad7d2`, etc.
6. **Profit Taking:** The attacker interacts with Uniswap V3 (`0x1111111254EEB25477B68fb85Ed929f73A960582`) to swap tokens. This suggests the attacker is converting the exploited assets into a more liquid form.

The exact method by which the integer underflow in `balanceOf` is used to profit is unclear without the source code. However, the combination of contract creation, `balanceOf` manipulation, interaction with a proxy contract, token deposits, and swaps on Uniswap suggests a complex exploit designed to drain assets from the victim contract or related protocols.

## Rugpull Detection
While the attack is not a simple rugpull, some elements are suspicious:

- **Contract Creation and Exploitation:** The attacker creates the victim contract and then immediately begins exploiting it. This suggests malicious intent from the outset.
- **Complex Interactions:** The use of multiple contracts and protocols makes it difficult to fully understand the attack without source code. This obfuscation is a common tactic in sophisticated rugpulls or exploits.
- **Privilege Function Calls:** The numerous calls to `_SIMONdotBLACK_` on various addresses suggest that the attacker is setting permissions or roles on these contracts. This could be a sign of setting up a backdoor or other malicious functionality. Further investigation is needed to understand the exact purpose of this function.

However, there are also elements that do not clearly indicate a rugpull:

- **No Obvious Liquidity Removal:** The transactions do not show a clear pattern of the contract owner removing liquidity from a pool.
- **No Clear Backdoor Function:** The provided data does not reveal a function that allows the owner to directly drain funds or bypass security mechanisms.

**Conclusion:** The attack is more complex than a typical rugpull, but the suspicious contract creation, exploitation, and privilege function calls warrant further investigation. The attacker is likely exploiting a vulnerability in the victim contract to manipulate balances and drain assets.
