# Raft Protocol - Security Analysis (Trace + Slither)

# Security Incident Analysis Report

## Attack Overview
This report analyzes a potential rugpull attack targeting the InterestRatePositionManager contract. The attacker deployed a malicious contract and performed a series of transactions that exploited a reentrancy vulnerability and potentially other issues to drain funds. The analysis focuses on identifying the exploited contract, the vulnerability, and the attack sequence.

## Contract Identification
- Attacker Contract: `0xc1f2b71A502B551a65Eee9C96318aFdD5fd439fA`
    - This contract deploys other contracts and interacts with the victim contract. It's the source of the attack.
- Victim Contract: `0x9AB6b21cDF116f611110b048987E58894786C244` (InterestRatePositionManager)
    - This contract manages interest rate positions, and the attacker drained funds from it. The Slither analysis highlights several vulnerabilities, including reentrancy and unchecked transfers.
- Helper Contracts: Several contracts were created by the attacker, including `0xfdc0feaa3f0830aa2756d943c6d7d39f1d587110`, `0x67ffc92eda90e744c45864b0bd70acf1738ff780`, `0x30481c87e3f221e1689126f92a4df9f890c6ade5`, `0x9a2b82c00bc281fabe23f5b720f0883cf14ebe94`, `0x16362eb29827b818f58b8f3d2358d6a53fae4c5b`, `0x6f9c91218f29a69e31168beed0c987e22d88cfa4`, `0x44f8b3b0fb808150f014d8f319b15acee3d61ff3`, `0xba1afff81bf736b04b8e863d95f5e3bdc3fb3380`, `0xe16e1c106fa2d19f993f3928bdee06e5eac6f520`, `0x011992114806e2c3770df73fa0d19884215db85f`, and `0x043f64A4add524457F22B85FE8ee58bAF0edeC02`. These contracts likely implement malicious logic to exploit the vulnerabilities in the victim contract.

## Vulnerability Analysis
The Slither analysis of the `InterestRatePositionManager` contract (`0x9AB6b21cDF116f611110b048987E58894786C244`) reveals several security vulnerabilities, including:

1. **Reentrancy:** The `managePosition` function is vulnerable to reentrancy attacks. This is due to external calls to `PermitHelper.applyPermit`, `_adjustDebt`, `_adjustCollateral`, and `_checkValidPosition` before updating the state. This allows an attacker to re-enter the function and potentially manipulate the state of the contract.

```solidity
    function managePosition(
        IERC20 collateralToken,
        address position,
        uint256 collateralChange,
        bool isCollateralIncrease,
        uint256 debtChange,
        bool isDebtIncrease,
        uint256 maxFeePercentage,
        ERC20PermitSignature memory permitSignature
    ) external onlyDepositedCollateralTokenOrNew(position, collateralToken) lock(position) {
        require(collateralToken != IERC20(address(0)), "PM: collateral token cannot be address 0");
        require(position != address(0), "PM: position cannot be address 0");
        require(collateralChange <= type(uint256).max / 2, "PM: collateral change too high");
        require(debtChange <= type(uint256).max / 2, "PM: debt change too high");
        require(maxFeePercentage <= MathUtils._100_PERCENT, "PM: max fee % too high");

        if (permitSignature.v != 0) {
            PermitHelper.applyPermit(permitSignature, msg.sender, address(this));
        }

        (IERC20Indexable raftCollateralToken, IERC20Indexable raftDebtToken) = _getRTokens(collateralToken);

        (uint256 positionDebt, uint256 positionCollateral) = _getPositionValues(collateralToken, position);

        // debtBefore is used to calculate the borrowing fee, so we need to fetch it before adjusting the debt
        uint256 debtBefore = positionDebt;

        _adjustDebt(position, collateralToken, raftDebtToken, debtChange, isDebtIncrease, maxFeePercentage);

        _adjustCollateral(collateralToken, raftCollateralToken, position, collateralChange, isCollateralIncrease);

        // if the debt is being reduced to 0, then we can close the position
        if (!isDebtIncrease && (debtChange == type(uint256).max || (debtBefore != 0 && debtChange == debtBefore))) {
            _closePosition(raftCollateralToken, raftDebtToken, position, false);
            return;
        }

        _checkValidPosition(collateralToken, positionDebt, positionCollateral);

        // if this is a new position, then we need to set the collateral token for the position
        if (debtBefore == 0) {
            collateralTokenForPosition[position] = collateralToken;
            emit PositionCreated(position, collateralToken);
        }
    }
```

2. **Unchecked Transfers:** The `ERC20RMinter._mintR` and `ERC20RMinter._burnR` functions ignore the return value of `r.transfer` and `r.transferFrom`, respectively. This can lead to unexpected behavior if the token transfer fails.

```solidity
    function _mintR(address to, uint256 amount) internal lockCall {
        unlockCall();
        _mint(address(this), amount);
        ERC20 r = ERC20(underlying);
        bytes memory emptySignature;
        positionManager.managePosition(IERC20(address(this)), address(this), amount, true, amount, true, 1e18, emptySignature);
        r.transfer(to, amount); // return value ignored
    }

    function _burnR(address from, uint256 amount) internal lockCall {
        unlockCall();
        ERC20 r = ERC20(underlying);
        bytes memory emptySignature;
        r.transferFrom(from, address(this), amount); // return value ignored
        positionManager.managePosition(IERC20(address(this)), address(this), amount, false, amount, false, 1e18, emptySignature);
        _burn(address(this), amount);
    }
```

3. **Dangerous Strict Equalities:** The contract uses strict equality (`==`) in several places, which can be problematic due to potential rounding errors or other unexpected behavior.

## Exploitation Mechanism
Based on the transaction data and Slither analysis, the attacker likely exploited the reentrancy vulnerability in the `managePosition` function. The attacker could have re-entered the function multiple times, manipulating the state of the contract and draining funds.

Here's a potential reconstruction of the attack sequence:

1. **Contract Creation:** The attacker deployed the malicious contract `0xc1f2b71A502B551a65Eee9C96318aFdD5fd439fA`.
2. **Initial Deposits:** The attacker deposited a small amount of collateral into the `InterestRatePositionManager` contract.
3. **Reentrancy Trigger:** The attacker called the `managePosition` function, which triggered an external call to a malicious contract.
4. **Malicious Re-entry:** The malicious contract re-entered the `managePosition` function before the initial call completed.
5. **State Manipulation:** The attacker manipulated the state of the contract during the re-entry, potentially minting or burning tokens in an unauthorized manner.
6. **Repeat Re-entry:** The attacker repeated steps 4 and 5 multiple times, maximizing the amount of funds drained from the contract.
7. **Withdrawal:** The attacker withdrew the drained funds from the `InterestRatePositionManager` contract.

**Evidence:**
- The transaction trace shows numerous calls to `managePosition` from the attacker contract.
- The Slither analysis confirms the presence of a reentrancy vulnerability in the `managePosition` function.
- The attacker contract created other contracts, which were likely used to implement the malicious re-entry logic.

**Rugpull Detection:**
- The attacker deployed a malicious contract and used it to drain funds from the `InterestRatePositionManager` contract.
- The attacker exploited a reentrancy vulnerability in the `managePosition` function.
- The attacker created other contracts to implement the malicious re-entry logic.
- The attacker drained funds from the `InterestRatePositionManager` contract, indicating a rugpull.

Based on the analysis, the attacker performed a rugpull by exploiting a reentrancy vulnerability in the `InterestRatePositionManager` contract. The attacker deployed a malicious contract, deposited a small amount of collateral, and then used the reentrancy vulnerability to drain funds from the contract.
