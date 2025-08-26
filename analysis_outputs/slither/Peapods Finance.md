# Peapods Finance - Security Analysis (Trace + Slither)

# Security Incident Analysis Report

## Attack Overview
The attack appears to involve the exploitation of a reentrancy vulnerability within the `DecentralizedIndex` contract, potentially in conjunction with the `TokenRewards` contract. The attacker leverages this vulnerability to manipulate token balances and potentially drain funds. The `start()` function in the attacker contract likely initiates the exploit.

## Contract Identification
- Attacker Contract: `0x928B2DAe97FC5d40Cb0552815fb5ab071103e20a` - This contract initiated the transaction and received the value. It's the attacker's contract.
- Victim Contract: `0xdbB20A979a92ccCcE15229e41c9B082D5b5d7E31` - Based on the Slither analysis, this contract, which includes `DecentralizedIndex`, `TokenRewards`, and `WeightedIndex` contracts, contains several reentrancy vulnerabilities. The `DecentralizedIndex` contract's `_transfer` and `addLiquidityV2` functions are flagged with reentrancy issues due to external calls to `ITokenRewards.depositFromDAI(0)` during fee swaps and liquidity additions. The `TokenRewards` contract also has reentrancy vulnerabilities in `_addShares`, `_removeShares`, `_depositRewards`, and `depositFromDAI` functions. These vulnerabilities, combined with the transaction trace showing a high gas usage and numerous subtraces, suggest this contract was the target of the exploit.
- Helper Contracts: None identified from the provided information.

## Vulnerability Analysis
The Slither report highlights several reentrancy vulnerabilities. The most likely candidate for exploitation is the reentrancy in `DecentralizedIndex._transfer` function:

```solidity
function _transfer(address sender, address recipient, uint256 amount) internal override {
    require(!_swapping, "Swapping");
    super._transfer(sender, recipient, amount);

    if (sender == address(this) || recipient == address(this)) {
        return;
    }

    uint256 _min = totalSupply() / 10000;
    uint256 _bal = balanceOf(sender);

    _swapping = true;
    if (_bal >= _min * 100) {
        _feeSwap(_min * 100);
    } else if (_bal >= _min * 20) {
        _feeSwap(_min * 20);
    } else {
        _feeSwap(_min);
    }
    _swapping = false;
}

function _feeSwap(uint256 _amount) internal {
    address[] memory path = new address[](2);
    path[0] = DAI;
    path[1] = rewardsToken;
    IUniswapV2Router02(V2_ROUTER).swapExactTokensForTokensSupportingFeeOnTransferTokens(_amount, 0, path, _rewards, block.timestamp);
    ITokenRewards(_rewards).depositFromDAI(0);
}
```

The `_transfer` function calls `_feeSwap`, which then calls `ITokenRewards(_rewards).depositFromDAI(0)`. The `depositFromDAI` function in `TokenRewards` has a reentrancy vulnerability. This allows an attacker to re-enter the `_transfer` function before the initial call to `depositFromDAI` completes, potentially manipulating balances and draining funds.

Another potential reentrancy vulnerability exists in `DecentralizedIndex.addLiquidityV2`:

```solidity
function addLiquidityV2(uint256 _idxLPTokens, uint256 _daiLPTokens, uint256 _slippage) external onlyOwner {
    uint256 _idxTokensBefore = balanceOf(_msgSender());
    _transfer(_msgSender(), address(this), _idxLPTokens);
    _approve(address(this), V2_ROUTER, _idxLPTokens);
    IERC20(DAI).safeTransferFrom(_msgSender(), address(this), _daiLPTokens);
    IERC20(DAI).safeIncreaseAllowance(V2_ROUTER, _daiLPTokens);
    IUniswapV2Router02(V2_ROUTER).addLiquidity(address(this), DAI, _idxLPTokens, _daiLPTokens, (_idxLPTokens * (1000 - _slippage)) / 1000, (_daiLPTokens * (1000 - _slippage)) / 1000, _msgSender(), block.timestamp);
    IERC20(DAI).safeTransfer(_msgSender(), IERC20(DAI).balanceOf(address(this)) - _daiBefore);
    _transfer(address(this), _msgSender(), balanceOf(address(this)) - _idxTokensBefore);
    emit AddLiquidity(_msgSender(), _idxLPTokens, _daiLPTokens);
}
```

This function also calls `_transfer`, leading to the same reentrancy vulnerability described above.

## Exploitation Mechanism
1.  The attacker calls the `start()` function in their contract (`0x928B2DAe97FC5d40Cb0552815fb5ab071103e20a`).
2.  The `start()` function likely initiates a transfer of tokens to trigger the vulnerable `_transfer` function in the `DecentralizedIndex` contract.
3.  The `_transfer` function calls `_feeSwap`, which then calls `ITokenRewards(_rewards).depositFromDAI(0)`.
4.  Before `depositFromDAI` completes, the attacker's contract re-enters the `_transfer` function, potentially by calling a function that triggers another transfer or liquidity addition.
5.  This re-entry allows the attacker to manipulate token balances within the `DecentralizedIndex` and `TokenRewards` contracts, potentially draining funds.

The high gas usage (896664) and the large number of subtraces (99) in the transaction trace strongly suggest a reentrancy attack, as these attacks typically involve multiple nested calls.

The provided information does not indicate a rugpull. There is no evidence of the contract owner removing liquidity, modifying privileged functions, or performing suspicious token transfers.
