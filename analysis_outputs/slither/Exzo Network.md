# Exzo Network - Security Analysis (Trace + Slither)

# Security Incident Analysis Report

## Attack Overview
This report analyzes a potential rugpull attack targeting the EXZO token contract (`0xD098A30AE6C4A202DAD8155DC68e2494eBAc871c`). The attacker, `0x3160ef53c7b5968f6a3eed0c3659b982603e0622`, appears to have used owner privileges to mint tokens, modify fees, and potentially exclude themselves from fees before transferring tokens to other addresses. The analysis focuses on identifying the exploitation pattern and reconstructing the attack sequence.

## Contract Identification
- Attacker Contract: `0x3160ef53c7b5968f6a3eed0c3659b982603e0622` - This address initiated several transactions modifying the EXZO token contract's parameters, suggesting control over the contract.
- Victim Contract: `0xD098A30AE6C4A202DAD8155DC68e2494eBAc871c` - This is the EXZO token contract. Multiple transactions from the attacker target this contract, modifying its state (fees, max transaction percentage, blacklisting, minting). The slither analysis confirms this is the EXZO contract.
- Helper Contracts: `0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD` - This address receives a call from the attacker to the `execute` function. It is likely a proxy or multi-sig wallet used by the attacker.

## Vulnerability Analysis
The EXZO contract has several concerning functions that, when combined, enable a rugpull:

1.  **`_mint(address,uint256)` (Wrapped-tokens/XZO.sol#1003-1016):** This function allows the owner to mint new tokens.
    ```solidity
    function _mint(address account, uint256 amount) internal virtual {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _beforeTokenTransfer(address(0), account, amount);

        _totalSupply += amount;
        _balances[account] += amount;
        emit Transfer(address(0), account, amount);

        _afterTokenTransfer(address(0), account, amount);
    }
    ```
    The `require` statement only checks if the caller is the owner. There is no limit on the amount of tokens that can be minted.

2.  **`updateFees(uint256,uint256,uint256)` (Wrapped-tokens/XZO.sol):** This function allows the owner to change the liquidity, donation, and burn fees.
    ```solidity
    function updateFees(uint256 liquidityFee, uint256 donationFee, uint256 burnFee) public onlyOwner {
        _liquidityFee = liquidityFee;
        _donationFee = donationFee;
        _burnFee = burnFee;
        require(_liquidityFee + _donationFee + _burnFee <= 1000, "Total fees must be less than 10%");
    }
    ```
    The owner can set these fees to any value as long as the total is less than 10%.

3.  **`ExcludeOrIncludeFromFee(address,bool)` (Wrapped-tokens/XZO.sol#971-977):** This function allows the owner to exclude or include an address from fees.
    ```solidity
    function ExcludeOrIncludeFromFee(address Account, bool value) public onlyOwner {
        isExcludedFromFee[Account] = value;
    }
    ```
    This function allows the owner to exclude themselves from fees, enabling them to transfer tokens without incurring any charges.

4.  **`setDonationWallet(address)` (Wrapped-tokens/XZO.sol#793):** This function allows the owner to set the donation wallet address.
    ```solidity
    function setDonationWallet(address _donationWallet) public onlyOwner {
        donationWallet = _donationWallet;
    }
    ```
    The owner can set the donation wallet to any address, potentially directing funds to an attacker-controlled address. The Slither analysis also notes that this function lacks a zero-address check.

## Exploitation Mechanism
The attacker leveraged the owner privileges and the vulnerabilities described above to perform a rugpull. The attack sequence is as follows:

1.  **Fund the Attacker Contract:**
    - Tx Hash: `0xefef22c8afa717e40c042baf644b26a2db7b18f3d0fe8b3002dd1b682c013056`
    - A small amount of ETH (0.1 ETH) is transferred to the attacker contract.

2.  **Set Max Transaction Percentage:**
    - Tx Hash: `0xc511059f2872f9a85d7f47968e7524e5cd769c7ccf4db410dc990a53a03c22df`
    - Function: `setMaxTxPercentage(uint256)`
    - The attacker sets the maximum transaction percentage. The exact value is not clear from the provided data, but this step is likely to allow for larger transfers later.

3.  **Mint Tokens:**
    - Tx Hash: `0xf3f77920919aa9a0d02ce2860d0c974645a179904c20d766c8f6eaf6c344003f`
    - Function: `_mint(address,uint256)`
    - The attacker mints an unspecified amount of tokens to themselves.

4.  **Mint Tokens (Again):**
    - Tx Hash: `0xc5cebbe49d907e68729393ff41c934bf8788dc3bc76ac00e5f1585a619c35b41`
    - Function: `_mint(address,uint256)`
    - The attacker mints more tokens to themselves.

5.  **Set Donation Wallet:**
    - Tx Hash: `0x2ab6552fb7c75f04eecfabb3be378e6d61b1e94d525699b3123f0877d8bcb88d`
    - Function: `setDonationWallet(address)`
    - The attacker sets the donation wallet to an address they control.

6.  **Update Fees (Multiple Times):**
    - Tx Hashes: `0x36fc0de8f44a4034186ae91936d96732b1836be00003292775d5979a3d18bbe2`, `0x4fa5f9845146c39be47c5450e02dee0524cb08612ef446c60e7f886088ddab3a`, `0x16a92218931837e7c3e26758183154a8c5a3731c2add909affc6c1c4b4ec8f26`
    - Function: `updateFees(uint256,uint256,uint256)`
    - The attacker modifies the liquidity, donation, and burn fees. The specific values are not available, but it's likely they are setting them to high values to drain funds from transfers.

7.  **Set Automatic Market Maker:**
    - Tx Hash: `0x3681ac964134c8eea4313d76d0ffb0eb00d4ac2c5e05ba54d1d3162e2922d066`
    - Function: `SetAutomaticMarketMaker(address,bool)`
    - The attacker sets an address as an automatic market maker. This could be used to manipulate the price or facilitate transfers.

8.  **Transfer Tokens:**
    - Tx Hashes: `0xc05cf8de595a0c27bdd0f19ecd78ea92a30cdc67b2f732040120e0e9fa6e2f86`, `0xb773d82b16240527df45875aef3f8775dfa1b90695a77b808bc05808cc7e7954`, `0x3dc1460707ce8036aea33ea2852c568ebbb91d7d6a59c53114baffba45c56288`, `0xf44f538802917c7f92ec5e2fcc3157aeb2fc26d9baa784fbcd0cd70e659f3d03`
    - The attacker transfers tokens to various addresses, including `0xDf2752AD6cF2358d1836dDA2FF6Fa61bb742c4E7`, `0x110bEd5780249cDe205E894cE88A3d9CeE1556f3`, and `0x05c35BD4c216931E2328AF965a49748fC36e15Ea`.

9.  **Exclude from Fees:**
    - Tx Hash: `0x68c03b0e9f6f138ead8e4acac97e11041891084b72a2474fb84e918329bf2a8c`
    - Function: `ExcludeOrIncludeFromFee(address,bool)`
    - The attacker likely excludes their own address from fees, allowing them to transfer the remaining tokens without incurring charges.

10. **Execute Function:**
    - Tx Hash: `0xad2ad1fd40628af2a20046e4b7b0c0c0aeb26ec8a73df1a065a2103ab42f59b7`
    - Function: `execute(bytes,bytes[],uint256)`
    - The attacker calls the `execute` function on the address `0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD`. The purpose of this call is unclear without further analysis of the contract at that address.

The combination of minting tokens, modifying fees, and excluding themselves from fees strongly suggests a rugpull. The attacker gained control of the token supply and likely drained liquidity pools by selling the minted tokens, leaving other holders with worthless tokens.
