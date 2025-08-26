# Mirage Finance - Security Analysis (Trace + Slither)

# Security Incident Analysis Report

## Attack Overview
This incident appears to be a rugpull targeting the MRGTOKEN token contract. The attacker likely exploited privileged functions or a combination of vulnerabilities to drain liquidity from the token's pool. The Slither analysis highlights reentrancy vulnerabilities and other potential issues that could have been leveraged.

## Contract Identification
- Attacker Contract: `0x4843E00Ef4c9f9f6e6aE8d7b0A787f1C60050b01` - This address initiated the transaction that resulted in the loss of funds. It's likely a contract deployed by the attacker to interact with the victim contract.
- Victim Contract: `0x0d99f24e96c42432a758124496f4ce9c67f6aa7b` (MRGTOKEN) - This is the contract where the vulnerability exists. The transaction trace shows that the attacker's transaction directly interacts with this contract. The Slither analysis also points to several vulnerabilities within this contract.
- Helper Contracts: `0x7a250d5630b4cf539739df2c5dacb4c659f2488d` (Uniswap V2 Router), `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH) - These are standard contracts used for swapping tokens on Uniswap.

## Vulnerability Analysis
The Slither analysis of the MRGTOKEN contract (`0x0d99f24e96c42432a758124496f4ce9c67f6aa7b`) reveals several potential vulnerabilities:

1.  **Reentrancy in `_transfer` function:**
    ```solidity
    function _transfer(
        address sender,
        address recipient,
        uint256 amount
    ) internal virtual {
        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        if(_isBlacklisted[sender] || _isBlacklisted[recipient]){
            revert("Blacklisted Address");
        }
        if (inSwap) { return _basicTransfer(sender, recipient, amount); }

        uint256 contractTokenBalance = balanceOf(address(this));

        bool canSwap = contractTokenBalance >= minimumTokens;

        if( canSwap && !isSwapping && swapAndLiquifyEnabled && recipient != uniswapV2Pair ) {
            swapAndLiquify(contractTokenBalance);
        }

        bool takeBurn = false;
        if(_liqBurnEnabled && recipient == uniswapV2Pair && sender != address(this)){
            takeBurn = true;
        }

        if(takeBurn){
            liqBurnAt();
        }

        //indicates if fee is on or off
        bool takeFee = true;

        //if any condition is met, fee is off
        if(_isExcludedFromFee[sender] || _isExcludedFromFee[recipient]) {
            takeFee = false;
        }

        if (takeFee) {
            uint256 finalAmount = takeTxFees(sender, recipient, amount);
            _balances[sender] = _balances[sender].sub(amount, Insufficient Balance);
            _balances[recipient] = _balances[recipient].add(finalAmount);
        } else {
            _basicTransfer(sender, recipient, amount);
        }
    }
    ```
    The `_transfer` function contains external calls to `swapAndLiquify` and `liqBurnAt`. These calls can potentially lead to reentrancy attacks, especially since state variables like `_balances` are modified after these external calls.  The `swapAndLiquify` function performs a token swap on Uniswap, and the `liqBurnAt` function interacts with the Uniswap pair.

2.  **Missing Events:**
    The Slither report highlights missing events for critical state changes, such as changes to `_maxTxAmount`, `_walletMax`, and `minimumTokens`. This makes it difficult to monitor the contract's behavior and detect suspicious activity.

3.  **Incorrect Solidity Version:**
    The contract uses a Solidity version with known severe issues.

## Exploitation Mechanism
Based on the transaction trace and the Slither analysis, the following attack sequence is likely:

1.  **Attacker calls a function on the Attacker Contract:** The transaction `0xb3456a338d7b3e7936a4d08b34e265818c116b7871baef8df1492a35f9f3b1bc` originates from the attacker contract `0x4843E00Ef4c9f9f6e6aE8d7b0A787f1C60050b01` and calls the MRGTOKEN contract `0x0d99f24e96c42432a758124496f4ce9c67f6aa7b`. The input `0x167d9279` corresponds to the `removeLimits()` function.

2.  **`removeLimits()` function is called:** This function sets `_maxTxAmount` and `_walletMax` to `_totalSupply`, effectively removing any restrictions on transaction amounts and wallet holdings. This is a critical step in preparing for the rugpull.

3.  **Attacker transfers tokens:** After removing the limits, the attacker transfers a large amount of MRGTOKEN to the Uniswap V2 Router (`0x7a250d5630b4cf539739df2c5dacb4c659f2488d`). This triggers the `_transfer` function in the MRGTOKEN contract.

4.  **`swapAndLiquify` is triggered:** The `_transfer` function's logic likely triggers the `swapAndLiquify` function because the contract's token balance exceeds `minimumTokens`. This function swaps a portion of the MRGTOKEN held by the contract for ETH and adds liquidity to the Uniswap pool.

5.  **ETH is transferred to the attacker:** The `swapAndLiquify` function transfers the ETH obtained from the swap to the `wallet` address, which is likely controlled by the attacker. This effectively drains the liquidity from the pool. The trace shows `0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2` (WETH) transferring `6360026517476820709` wei to the MRGTOKEN contract, which is then transferred to the attacker's contract.

6.  **Rugpull Complete:** The attacker now holds a significant amount of ETH, and the MRGTOKEN pool is depleted, rendering the token worthless.

**Rugpull Detection:**

*   **Privileged Functions:** The `removeLimits()` function is a clear indicator of a rugpull setup. It allows the contract owner to bypass safety mechanisms and manipulate the token's supply and distribution.
*   **Sudden Removal of Limits:** The timing of the `removeLimits()` call immediately before the large transfer to the Uniswap router is highly suspicious.
*   **Draining Liquidity:** The transfer of ETH to the attacker's contract confirms that liquidity was drained from the pool.

## Conclusion
This incident is a clear example of a rugpull. The attacker exploited privileged functions in the MRGTOKEN contract to remove transaction limits, transfer a large amount of tokens, and drain liquidity from the Uniswap pool. The Slither analysis highlights several vulnerabilities that could have been exploited, and the transaction trace provides evidence of the attack sequence.
