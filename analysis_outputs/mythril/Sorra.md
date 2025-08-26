# Sorra - Security Analysis (Trace + Mythril)

# Security Incident Analysis Report

## Attack Overview
This incident appears to be a sophisticated exploit involving a newly deployed contract (`0xB575b2599B9dCf242BB9dCA60DC2aD36a1cA8CD7`) and its interaction with other protocols, potentially including Uniswap V2. The attacker deployed a contract, set its implementation, claimed tokens, deposited funds into another contract, and then used a `metaRoute` function, ultimately transferring funds to their own address. The lack of vulnerabilities reported by Mythril on the victim contract suggests the exploit lies in the interaction between contracts or a logical flaw rather than a simple code-level vulnerability. The repeated calls to Uniswap V2 and the transfer of ETH to the attacker suggest a potential manipulation of price or liquidity within the Uniswap V2 pool.

## Contract Identification
- Attacker Contract: `0xdc8076c21365a93aaC0850B67e4cA5fDeC5FAb9b`
    - This address initiated all transactions and appears to be the primary controller of the attack. It deployed the initial contract and called all subsequent functions.
- Victim Contract: `0xFa39257C629F9A5DA2c0559deBe2011eEF7C1E9f`
    - This contract receives the `setImpl` call from the attacker, suggesting it's a proxy contract. The attacker then calls the `claim` function multiple times, indicating this contract is likely where the initial token claiming occurs. The traces show interaction with Uniswap V2 during the `claim` calls, indicating this contract is involved in token swapping or liquidity manipulation.
- Helper Contracts:
    - `0xB575b2599B9dCf242BB9dCA60DC2aD36a1cA8CD7`: This is the contract created by the attacker in the first transaction. It's likely the implementation contract set by the attacker in the proxy contract `0xFa39257C629F9A5DA2c0559deBe2011eEF7C1E9f`.
    - `0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b`: This contract receives deposits from the attacker. Its purpose is unclear without further analysis of its code, but it's likely part of the overall exploit strategy.
    - `0xf621Fb08BBE51aF70e7E0F4EA63496894166Ff7F`: This contract receives a `metaRoute` call from the attacker. Its purpose is unclear without further analysis of its code, but it's likely part of the overall exploit strategy.

## Vulnerability Analysis
The Mythril analysis found no vulnerabilities in the victim contract. However, the transaction traces reveal a pattern of token claiming and swapping on Uniswap V2, followed by deposits and a `metaRoute` call. This suggests the vulnerability lies in a logical flaw or a manipulation of the Uniswap V2 price oracle.

The `claim` function in the proxy contract `0xFa39257C629F9A5DA2c0559deBe2011eEF7C1E9f` is likely the entry point for the exploit. The traces for the `claim` calls (e.g., `0x6439d63cc57fb68a32ea8ffd8f02496e8abad67292be94904c0b47a4d14ce90d`) show multiple calls to Uniswap V2 (`0x7a250d5630b4cf539739df2c5dacb4c659f2488d`) and the transfer of value to the attacker (`0xdc8076c21365a93aaC0850B67e4cA5fDeC5FAb9b`). The calls to `0xe021baa5b70c62a9ab2468490d3f8ce0afdd88df`, `0x1fce9237f50dbdaf4ee9d0791bdbb2778ef81505`, and `0xdb69c17872c5872c6ae631bb5526d95aae65ed35` within the `claim` traces suggest a complex interaction with other contracts, potentially related to price manipulation or arbitrage.

Without the source code for `0xFa39257C629F9A5DA2c0559deBe2011eEF7C1E9f` and `0xB575b2599B9dCf242BB9dCA60DC2aD36a1cA8CD7`, it's impossible to pinpoint the exact vulnerable code segment. However, the traces strongly suggest the `claim` function, in conjunction with the attacker-controlled implementation contract, is the source of the exploit.

## Exploitation Mechanism
1. **Contract Deployment and Implementation Setting:** The attacker first deploys a contract (`0xB575b2599B9dCf242BB9dCA60DC2aD36a1cA8CD7`) using transaction `0x1e83b95a9f946a03bcc6ce2887434c2979e0f3adcb6f44f205751c14c5b27bda`. This contract likely contains malicious logic designed to exploit the target protocol.
2. **Implementation Setting in Proxy:** The attacker then calls the `setImpl` function on the proxy contract `0xFa39257C629F9A5DA2c0559deBe2011eEF7C1E9f` using transaction `0x285d2eb16278d86085df6b9f192b5fc39b8f66e4d36304b1d24c6bfc189a3701`. This sets the implementation of the proxy to the attacker-controlled contract.
3. **Token Claiming and Swapping:** The attacker calls the `claim` function on the proxy contract multiple times (transactions `0x6439d63cc57fb68a32ea8ffd8f02496e8abad67292be94904c0b47a4d14ce90d`, `0x03ddae63fc15519b09d716b038b2685f4c64078c5ea0aa71c16828a089e907fd`, `0xf1a494239af59cd4c1d649a1510f0beab8bb78c62f31e390ba161eb2c29fbf8b`, `0x09b26b87a91c7aea3db05cfcf3718c827eba58c0da1f2bf481505e0c8dc0766b`). These calls trigger a series of internal calls, including interactions with Uniswap V2, ultimately resulting in the transfer of ETH to the attacker. The specific mechanism of this transfer is unclear without the source code, but it likely involves manipulating the price oracle or exploiting a flaw in the token swapping logic.
4. **Deposits:** The attacker deposits funds into contract `0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b` using transactions `0x768a6983ed719e07eeb5e2a52501125b3554ec583c8d553a09b72339e3bc74fd` and `0x6ee3b7864c032c8c9c97cb088f620396144345087f4771d35ef68612466aea57`.
5. **MetaRoute Call:** Finally, the attacker calls the `metaRoute` function on contract `0xf621Fb08BBE51aF70e7E0F4EA63496894166Ff7F` using transaction `0x0fcddf2e1a78d7eff65d7eeca567b1273e8ac4d8c829cbeb9682135c1625f8cb`. This call transfers 710,000,000,000,000,000 wei to the WETH contract, likely as part of the overall exploit.

## Rugpull Detection
Based on the available data, it is difficult to definitively classify this as a rugpull. However, several factors raise suspicion:

- **New Contract Deployment:** The attacker deployed a new contract specifically for this attack.
- **Proxy Pattern:** The use of a proxy contract allows the attacker to change the implementation at will, potentially introducing malicious logic after the initial deployment.
- **Rapid Exploitation:** The attack occurred shortly after the contract deployment, suggesting a pre-planned exploit.
- **Uniswap V2 Interaction:** The repeated calls to Uniswap V2 and the transfer of ETH to the attacker suggest a potential manipulation of price or liquidity within the Uniswap V2 pool.

Without further information about the project and the intended functionality of the contracts, it is impossible to definitively determine if this was a rugpull. However, the suspicious timing, the use of a proxy pattern, and the manipulation of Uniswap V2 raise serious concerns.
