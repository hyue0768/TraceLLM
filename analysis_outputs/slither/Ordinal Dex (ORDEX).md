# Ordinal Dex (ORDEX) - Security Analysis (Trace + Slither)

# Security Incident Analysis Report

## Attack Overview
This report analyzes a potential rugpull attack targeting the OrdinalDex token contract (`0x797885C0a6CfffCbc4D2e3C1ca0B4F07112dB6a3`). The analysis reveals a reentrancy vulnerability and other suspicious characteristics that suggest a rugpull.

## Contract Identification
- Attacker Contract: `0x797885C0a6CfffCbc4D2e3C1ca0B4F07112dB6a3` (OrdinalDex Token). This is the contract that was directly interacted with by external accounts. Slither analysis identifies reentrancy vulnerabilities.
- Victim Contract: `0x797885C0a6CfffCbc4D2e3C1ca0B4F07112dB6a3` (OrdinalDex Token). In this case, the token contract itself is the victim, as the attacker exploits vulnerabilities within it to drain value.
- Helper Contracts: None identified.

## Vulnerability Analysis
The Slither analysis highlights a critical reentrancy vulnerability in the `_transferFrom` function of the `OrdinalDex` contract:

```solidity
    function _transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) internal virtual {
        require(!isBlacklisted[sender], "You are blacklisted!");
        require(!isBlacklisted[recipient], "Recipient is blacklisted!");

        if(inSwapAndLiquify){ return; }

        // is it a trade
        if(recipient == uniswapV2Pair && ! isTxLimitExempt[sender]){
            require(amount <= _maxWalletAmount, "Exceeds maximum wallet amount.");
        }

        //Exchange tokens
        bool takefee = true;
        uint256 actions = 0;

        if (sender == owner || recipient == owner || sender == address(this) || recipient == address(this) || isTxLimitExempt[sender] || isTxLimitExempt[recipient]) {
            takefee = false;
        }

        if (shouldSwapBack()) {
            swapBackOrdinalEth(amount);
        }

        _transferTokens(
            sender,
            recipient,
            amount,
            takefee,
            actions
        );
    }

    function swapBackOrdinalEth(uint256 amount) private lockTheSwap {
        uint256 amountToSwap = takeOrdinalAmountAfterFees(
            balanceOf(address(this)),
            true,
            0
        );

        if (amountToSwap == 0) {
            return;
        }

        address[] memory path = new address[](2);
        path[0] = address(this);
        path[1] = uniswapV2Router.WETH();

        uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
            amountToSwap,
            0,
            path,
            address(this),
            block.timestamp
        );

        uint256 amountETHMarketing = address(this).balance;

        address(_taxWallet).transfer(amountETHMarketing);
    }
```

The `_transferFrom` function, used for transferring tokens, calls `swapBackOrdinalEth` if `shouldSwapBack` returns true. `swapBackOrdinalEth` swaps tokens for ETH and then transfers the ETH to the `_taxWallet`. The vulnerability lies in the fact that `_transferTokens` (which updates balances) is called *after* the external call to `swapBackOrdinalEth`. This allows a reentrancy attack: the attacker can call `_transferFrom` again within the `swapExactTokensForETHSupportingFeeOnTransferTokens` call, before the initial balances are updated.

## Exploitation Mechanism
The attacker exploits the reentrancy vulnerability in `_transferFrom` to repeatedly drain ETH from the contract. The attack sequence is as follows:

1. **Initial Setup:** The attacker likely obtains a significant amount of `OrdinalDex` tokens.
2. **Trigger `_transferFrom`:** The attacker initiates a token transfer that triggers the `shouldSwapBack` condition, causing `swapBackOrdinalEth` to be called.
3. **Reentrancy:** Inside `swapBackOrdinalEth`, the call to `uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens` allows the attacker to re-enter the `OrdinalDex` contract by calling `_transferFrom` again.
4. **Repeated Swaps:** The attacker repeats steps 2 and 3 multiple times within the initial `_transferFrom` call, each time triggering a token swap and ETH transfer to the `_taxWallet`. Because the balances haven't been updated yet, the attacker can repeatedly swap the same tokens.
5. **Balance Update:** Finally, the initial `_transferFrom` call completes, updating the balances.

The transaction data provided doesn't show the exact reentrancy calls, but the numerous calls to `_SIMONdotBLACK_(int8[],int224[],int256,int64,uint248[])` (which is the obfuscated name for a function, likely `_transferFrom`) from various addresses suggest multiple transfers are happening. Also, the `_taxWallet` address is likely controlled by the attacker, effectively draining the contract's ETH.
