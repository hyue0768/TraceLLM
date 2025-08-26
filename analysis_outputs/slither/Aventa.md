# Aventa - Security Analysis (Trace + Slither)

# Security Incident Analysis Report

## Attack Overview
This report analyzes a potential rugpull attack targeting the IntelliQuant protocol. The attacker deployed a contract and used it to interact with the protocol's staking and reward claiming mechanisms, potentially exploiting vulnerabilities in the `AventaRewardClaim` and `IntelliQuant_Staking` contracts. The analysis focuses on identifying the victim contract, the exploitation pattern, and reconstructing the attack sequence.

## Contract Identification
- Attacker Contract: `0x7c982E93d6B1eDE9626A84EbeafBC42e5991Dee8`
    - This contract was created by `0x0cdaa461d9d60ef84ded453fa1fbd3e2916f9016` and its purpose appears to be to deploy and interact with other contracts. It receives tokens from the created contracts, suggesting it's the beneficiary of the attack.
- Victim Contract: `0x33b860fc7787e9e4813181b227eaffa0cada4c73` (AventaRewardClaim and IntelliQuant_Staking)
    - This contract is identified as the victim because the attacker's contract interacts with it, and the Slither analysis reveals several vulnerabilities, including reentrancy and arbitrary `transferFrom` usage, which could be exploited to drain funds. The trace shows multiple calls to Uniswap to acquire tokens, which are then deposited into contracts that transfer value to the attacker.
- Helper Contracts:
    - `0xcfe54d8d11fb35eefc82b71cd5b6017dbfcce728`
    - `0xb45206a5a2cb07df79864a1d698af0bfab8c0ba4`
    - `0x085d6eab2082a07ca201cfbeb3eb77d783f621e7`
    - `0xb8a95da848e227c9d2471cc4154015a41611395e`
    - `0x3ae731008cacf7adedbc8511e2b41ec00a8c9a39`
    - `0xdc02f413d5d23c93a1e3c3e429552abfc43653c9`
    - `0x52d36302a8476f50b69bbab102d4ee831a79213a`
    - `0xa2b7383d2ef3ee691d94764ce5a76c0240d6ee25`
    - `0xe463162ba5609e8bb0b2c65f1cea61a0e2b95dae`
    - `0xf35a9daa97898bfa8a5c4f03aab8192bfe61918a`
    - `0xa04b26fc3316ce6f14b1d066c53d699e4a1fc5a1`
    - `0xc488df802b17b48c0ea516e030a911a445418fcb`
    - These contracts were created by `0x0cdaa461d9d60ef84ded453fa1fbd3e2916f9016` and appear to facilitate the transfer of value to the attacker contract.

## Vulnerability Analysis
The Slither analysis of the `AventaRewardClaim` and `IntelliQuant_Staking` contracts reveals several vulnerabilities:

1.  **Arbitrary `transferFrom` Usage (High Impact):**
    *   The `claim(address)` and `withdrawTokens(address,uint8,uint64)` functions in `AventaRewardClaim` use `Aventa.transferFrom(Owner, user, withdrawableAmount)`. This allows the contract to transfer tokens from the `Owner` to an arbitrary `user` without proper authorization from the `Owner`.
    ```solidity
    // AventaRewardClaim.sol
    function claim(address user) public onlyOwner Paused {
        require(!c_blacklist[user], "Account is blacklisted");
        uint256 withdrawableAmount = getClaimableAmount(user);
        require(withdrawableAmount > 0, "No available");
        require(Aventa.transferFrom(Owner,user,withdrawableAmount), "Token transfer failed c");
        c_blacklist[user] = true;
        emit UserBlacklisted(user);
        emit TokensClaimed(user, withdrawableAmount, block.timestamp);
    }
    ```
    ```solidity
    // AventaRewardClaim.sol
    function withdrawTokens(address user, uint8 _index, uint64 _eta) public onlyOwner Paused {
        UserInfo storage userData = Users[user];
        require(userData.depositsLength > 0, "No deposits found for this user");
        require(_index < userData.depositsLength, "Invalid index");
        require(block.timestamp >= _eta, "Eta not reached");
        uint256 withdrawableAmount = userData.DepositeToken[_index];
        uint256 lockTime = userData.depositetime[_index] + timeStep;
        require(block.timestamp > lockTime, "Lock time not reached");
        require(userData.lastWithdrawal == 0, "Already withdrawn");
        require(Aventa.transferFrom(Owner,user,withdrawableAmount), "Token transfer failed");
        userData.lastWithdrawal = block.timestamp;
        emit TokensClaimed(user, withdrawableAmount, block.timestamp);
    }
    ```
2.  **Reentrancy Vulnerability (Medium Impact):**
    *   The `claim(address)` function in `AventaRewardClaim` and `harvest(uint256)` in `IntelliQuant_Staking` are vulnerable to reentrancy. External calls to `transferFrom` and `transfer` are made before state variables are updated, allowing an attacker to potentially re-enter the function and drain more funds.
    ```solidity
    // AventaRewardClaim.sol
    function claim(address user) public onlyOwner Paused {
        require(!c_blacklist[user], "Account is blacklisted");
        uint256 withdrawableAmount = getClaimableAmount(user);
        require(withdrawableAmount > 0, "No available");
        require(Aventa.transferFrom(Owner,user,withdrawableAmount), "Token transfer failed c");
        c_blacklist[user] = true;
        emit UserBlacklisted(user);
        emit TokensClaimed(user, withdrawableAmount, block.timestamp);
    }
    ```
    ```solidity
    // IntelliQuant_Staking.sol
    function harvest(uint256 _index) public {
        require(isSpam[msg.sender] == false, "Account is spam!");
        UserInfo storage Users = userInfo[msg.sender];
        require(Users.DepositeToken.length > 0, "No deposits found for this user");
        require(_index < Users.DepositeToken.length, "Invalid index");
        uint256 lockTime = Users.depositetime[_index] + time;
        uint256 totalwithdrawAmount = Users.DepositeToken[_index];
        uint256 deductionfee;
        uint256 a;
        if (block.timestamp > lockTime) {
            totalwithdrawAmount = totalwithdrawAmount.add((totalwithdrawAmount * allocation[90]) / 100);
        } else {
            totalwithdrawAmount = totalwithdrawAmount.add((totalwithdrawAmount * allocation[1]) / 100);
        }
        uint256 deductionfee = (totalwithdrawAmount * deductionPercentage) / 100;
        uint256 taxMakeup = (deductionfee * taxMakeupPercentage) / 100;
        Token.transfer(msg.sender, totalwithdrawAmount + taxMakeup);
        Token.transfer(taxreceiver, deductionfee);
        Users.WithdrawReward = Users.WithdrawReward.add(Users.WithdrawAbleReward);
        Users.WithdrawAbleReward = 0;
        Users.WithdrawDepositeAmount = 0;
    }
    ```
3.  **Unchecked Transfer (High Impact):**
    *   The `harvest(uint256)` function in `IntelliQuant_Staking` uses `Token.transfer(msg.sender,totalwithdrawAmount + taxMakeup)` and `Token.transfer(taxreceiver,deductionfee)` without checking the return value. If the transfer fails, the state will still be updated, leading to a loss of funds.
    ```solidity
    // IntelliQuant_Staking.sol
    function harvest(uint256 _index) public {
        require(isSpam[msg.sender] == false, "Account is spam!");
        UserInfo storage Users = userInfo[msg.sender];
        require(Users.DepositeToken.length > 0, "No deposits found for this user");
        require(_index < Users.DepositeToken.length, "Invalid index");
        uint256 lockTime = Users.depositetime[_index] + time;
        uint256 totalwithdrawAmount = Users.DepositeToken[_index];
        uint256 deductionfee;
        uint256 a;
        if (block.timestamp > lockTime) {
            totalwithdrawAmount = totalwithdrawAmount.add((totalwithdrawAmount * allocation[90]) / 100);
        } else {
            totalwithdrawAmount = totalwithdrawAmount.add((totalwithdrawAmount * allocation[1]) / 100);
        }
        uint256 deductionfee = (totalwithdrawAmount * deductionPercentage) / 100;
        uint256 taxMakeup = (deductionfee * taxMakeupPercentage) / 100;
        Token.transfer(msg.sender, totalwithdrawAmount + taxMakeup);
        Token.transfer(taxreceiver, deductionfee);
        Users.WithdrawReward = Users.WithdrawReward.add(Users.WithdrawAbleReward);
        Users.WithdrawAbleReward = 0;
        Users.WithdrawDepositeAmount = 0;
    }
    ```

## Exploitation Mechanism
Based on the transaction trace and vulnerability analysis, the exploitation mechanism likely involves the following steps:

1.  **Contract Deployment:** The attacker deploys the initial contract `0x7c982E93d6B1eDE9626A84EbeafBC42e5991Dee8` using a CREATE transaction.
2.  **Helper Contract Creation:** The attacker's contract creates multiple helper contracts (`0xcfe54d8d11fb35eefc82b71cd5b6017dbfcce728`, `0xb45206a5a2cb07df79864a1d698af0bfab8c0ba4`, etc.).
3.  **Token Acquisition:** The helper contracts interact with Uniswap (`0x7a250d5630b4cf539739df2c5dacb4c659f2488d`) to acquire tokens, likely the tokens used in the IntelliQuant protocol.
4.  **Exploitation of `AventaRewardClaim` and `IntelliQuant_Staking`:** The helper contracts call functions in the `AventaRewardClaim` and `IntelliQuant_Staking` contracts, potentially exploiting the reentrancy or arbitrary `transferFrom` vulnerabilities to drain funds.
5.  **Value Transfer to Attacker:** The helper contracts transfer the drained tokens to the attacker's contract `0x7c982E93d6B1eDE9626A84EbeafBC42e5991Dee8`.

**Rugpull Indicators:**

*   **Suspicious Timing:** The sudden deployment of multiple contracts and interaction with the staking and reward claiming mechanisms within a short timeframe is suspicious.
*   **Value Consolidation:** The helper contracts transfer all acquired tokens to the attacker's contract, suggesting a coordinated effort to drain funds.
*   **Vulnerable Code:** The presence of reentrancy and arbitrary `transferFrom` vulnerabilities in the contracts indicates a lack of security awareness and increases the likelihood of a malicious intent.

**Conclusion:**

The evidence suggests a potential rugpull attack targeting the IntelliQuant protocol. The attacker exploited vulnerabilities in the `AventaRewardClaim` and `IntelliQuant_Staking` contracts to drain funds and consolidate them in their own contract. Further investigation is needed to confirm the exact exploitation steps and the extent of the damage.
