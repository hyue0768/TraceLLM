# Ordinal Dex (ORDEX) - Security Analysis (Trace + Mythril)

# Security Incident Analysis Report

## Attack Overview

This incident appears to be a rugpull attack targeting users who interacted with a contract deployed by the attacker. The attacker deployed a contract, lured users to approve it, and then used a privileged function to drain funds. The transactions show numerous calls to a function named `_SIMONdotBLACK_`, which is highly suspicious and indicative of a malicious contract. The function `workMyDirefulOwner` is also called, which is another indicator of a malicious contract.

## Contract Identification

- Attacker Contract: `0x797885C0a6CfffCbc4D2e3C1ca0B4F07112dB6a3`
    - Analysis: This contract receives numerous calls with the `_SIMONdotBLACK_` function, suggesting it's the central point of the attack. The transactions show approvals and transfers *to* this contract, indicating it's the attacker's contract and not the victim.

- Victim Contract: Based on the provided data, it's difficult to pinpoint a single victim contract. The attacker's contract `0x797885C0a6CfffCbc4D2e3C1ca0B4F07112dB6a3` is designed to steal funds from users who approve it. The victims are the addresses that called the `_SIMONdotBLACK_` function on the attacker's contract. There isn't a single "victim contract" in the traditional sense of a vulnerable protocol. The vulnerability lies in the users' trust and approval of the malicious contract.

- Helper Contracts: None are apparent from the data provided.

## Vulnerability Analysis

The vulnerability is not in a specific contract, but rather in the design of the attacker's contract and the users' interaction with it. The attacker's contract likely contains a malicious function (potentially within `_SIMONdotBLACK_` or `workMyDirefulOwner`) that, once approved by a user, allows the attacker to transfer the user's tokens to the attacker's address.

Without the attacker's contract code, it's impossible to provide the exact vulnerable code segment. However, the presence of a function like `_SIMONdotBLACK_` with such unusual naming strongly suggests it's a backdoor or malicious function. The function `workMyDirefulOwner` is also suspicious.

## Exploitation Mechanism

1. **Deployment:** The attacker deploys the contract `0x797885C0a6CfffCbc4D2e3C1ca0B4F07112dB6a3`.
2. **Luring:** The attacker lures users to interact with the contract, likely by promising rewards or other incentives. The users are tricked into calling the `_SIMONdotBLACK_` function.
3. **Approval:** The `_SIMONdotBLACK_` function likely triggers a token approval, granting the attacker's contract permission to transfer the user's tokens.
4. **Drainage:** After the approval, the attacker calls the `workMyDirefulOwner` function to transfer the approved tokens from the user's address to the attacker's address.

**Transaction Evidence:**

- Numerous transactions calling the `_SIMONdotBLACK_` function from different addresses: This indicates that many users were targeted by the attacker.
- Transactions calling the `workMyDirefulOwner` function: This confirms that the attacker was able to execute token transfers from the users' addresses.
- The `input` field of the transactions shows the function being called and the parameters being passed.

**Rugpull Confirmation:**

This incident is a clear rugpull. The attacker deployed a malicious contract, lured users to approve it, and then drained their funds. The unusual function names and the pattern of approvals followed by transfers are strong indicators of a rugpull attack.

