# Fire (FIRE) - Security Analysis (Trace + Slither)

# Security Incident Analysis Report

## Attack Overview
This incident appears to be a rugpull attack targeting the FireToken contract. The attacker deployed the FireToken contract, deposited initial liquidity, and then exploited a combination of privileged functions and potentially a reentrancy vulnerability to drain the contract's ETH balance.

## Contract Identification
- Attacker Contract: `0x81F48A87Ec44208c691f870b9d400D9c13111e2E` - This is the address that initiated the contract creation and subsequent transactions.
- Victim Contract: `0x18775475f50557b96C63E8bbf7D75bFeB412082D` (FireToken) - This contract received deposits from the attacker and had its ETH balance drained. The transactions show the attacker interacting with this contract's `deposit` function, and the Slither analysis identifies vulnerabilities within this contract.
- Helper Contracts: `0x9776C0ABE8aE3C9Ca958875128F1ae1D5afafCb8` - This contract was created by the attacker in the first transaction. It appears to be an intermediate contract used to interact with the FireToken contract.

## Vulnerability Analysis
The FireToken contract has several vulnerabilities, according to the Slither analysis:

1.  **Arbitrary ETH Sending:** The `sendETHToFee(uint256)` function allows the contract owner to send ETH to an arbitrary address, controlled by the `_taxWallet` variable. This is a privileged function that can be abused to drain the contract's ETH balance.

    ```solidity
    function sendETHToFee(uint256 amount) private {
        _taxWallet.transfer(amount);
    }
    ```

2.  **Reentrancy:** The `_transfer` function is vulnerable to reentrancy attacks. The `swapTokensForEth` function calls `uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens`, which can trigger a callback to the FireToken contract before the state is updated. This allows an attacker to recursively call `_transfer` and potentially manipulate the token balances.

    ```solidity
    function _transfer(
        address from,
        address to,
        uint256 amount
    ) private {
        // ...
        if (shouldSwapBack()) {
            swapTokensForEth(min(amount,min(contractTokenBalance,_maxTaxSwap)));
            uint256 contractETHBalance = address(this).balance;
            if(contractETHBalance > 0) {
                sendETHToFee(address(this).balance);
            }
        }
        // ...
    }
    ```

3.  **`tx.origin` Usage:** The `_transfer` function uses `tx.origin` for authorization, which is generally discouraged. This can be exploited by a malicious contract to trick users into performing actions they didn't intend.

    ```solidity
    require(_holderLastTransferTimestamp[tx.origin] < block.number,"Only one transfer per block allowed.");
    ```

## Exploitation Mechanism
The attack likely proceeded as follows:

1.  **Contract Deployment:** The attacker deployed the FireToken contract (`0x18775475f50557b96C63E8bbf7D75bFeB412082D`) using transaction `0x5b415454528128f12a699582a45254bd8554085247e1e8fcaa2893c77e83140d`. This transaction also created the helper contract `0x9776C0ABE8aE3C9Ca958875128F1ae1D5afafCb8`.

2.  **Initial Liquidity:** The attacker provided initial liquidity to the contract, likely by calling the `openTrading()` function. This function adds liquidity to the Uniswap V2 pair.

3.  **Deposits:** The attacker deposited a total of 6.1 ETH into the `0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b` contract using the `deposit` function.

4.  **ETH Drain:** The attacker then exploited the `sendETHToFee` function (or potentially a reentrancy vulnerability in `_transfer`) to drain the ETH balance of the FireToken contract. The `sendETHToFee` function directly transfers ETH to the `_taxWallet` address, which is controlled by the attacker.

5.  **Final Drain:** In the last transaction `0xf30fecc85de6a35cefd43d7cdd58bf1605c4f395523f64c2e8ce40d00cb8a056`, the attacker sends the remaining 0.1 ETH to the `0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc` contract.

**Evidence of Rugpull:**

*   **Privileged Functions:** The `sendETHToFee` function allows the owner to arbitrarily drain ETH from the contract.
*   **Sudden Drain:** The attacker suddenly drained the ETH balance of the FireToken contract after depositing initial liquidity.
*   **Timing:** The attacker performed the drain shortly after deploying the contract and adding liquidity.

Based on the analysis, this incident is classified as a rugpull attack. The attacker deployed a malicious contract with privileged functions and then drained the contract's ETH balance, leaving investors with worthless tokens.
