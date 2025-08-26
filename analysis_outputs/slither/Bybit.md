# Bybit - Security Analysis (Trace + Slither)

# Security Incident Analysis Report

## Attack Overview
This report analyzes a potential proxy contract exploit and possible rugpull involving multiple contracts. The attacker deploys contracts and then uses them to drain funds from other contracts. The victim contract appears to be `0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4`, a proxy contract.

## Contract Identification
- Attacker Contract: `0x0fa09C3A328792253f8dee7116848723b72a6d2e` - This address initiates all the transactions and deploys the contracts involved in the exploit.
- Victim Contract: `0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4` - This contract is identified as the victim because the attacker interacts with it using `execTransaction`, `sweepETH`, and `sweepERC20` functions to drain its assets. The Slither report also flags this proxy contract as having a potential issue with locked ether.
- Helper Contracts:
    - `0x96221423681A6d52E184D440a8eFCEbB105C7242`
    - `0x2444c026EbE6d476e97bAeB003071bea9C13A953`
    - `0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516`
These contracts are created by the attacker using the `_SIMONdotBLACK_` function, which suggests they are malicious contracts designed to interact with the victim.

## Vulnerability Analysis
The primary vulnerability appears to reside within the proxy contract `0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4`. The Slither report highlights several potential issues:

1.  **Locked Ether:** The proxy contract has a payable fallback function but lacks a corresponding withdrawal function. This means any ETH sent directly to the contract could be locked indefinitely.

    ```solidity
    // From crytic-export/etherscan-contracts/0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4-Proxy.sol
    contract Proxy {
        address public implementation;

        constructor(address _implementation) public {
            implementation = _implementation;
        }

        function () external payable { // This is the fallback function
            address _impl = implementation;
            assembly {
                let ptr := mload(0x40)
                calldatacopy(0x00, 0x00, calldatasize())
                let result := delegatecall(gas(), _impl, 0x00, calldatasize(), 0x00, 0x00)
                let size := returndatasize()
                returndatacopy(ptr, 0x00, size)
                switch result
                case 0 { revert(ptr, size) }
                default { return(ptr, size) }
            }
        }
    }
    ```

2.  **Assembly Usage:** The fallback function uses inline assembly, which can be more difficult to audit and may introduce vulnerabilities if not implemented correctly. The delegatecall in the assembly block is particularly sensitive, as it executes code in the context of the proxy contract, potentially allowing the implementation contract to modify the proxy's state.

3.  **Outdated Solidity Version:** The contract uses Solidity version `^0.5.3`, which contains known severe bugs.

The `execTransaction` function, present in some of the contracts targeted by the attacker, could be vulnerable if it doesn't properly validate the transaction being executed. This could allow the attacker to execute arbitrary code within the context of the target contract.

## Exploitation Mechanism
The attacker's strategy involves deploying contracts and then using privileged functions to drain funds. The attack sequence is as follows:

1.  **Contract Creation:** The attacker deploys several contracts using transactions like `0x84cd9d6cb84df9df4be638899f4a56053ed98042febd489ef3d51a3ed3652d40`, `0xd856376c6c3f1170af98371c43e0c4b2c7b94e1f54772222063497ec465949ff`, and `0xc47ac9038127cef763a1c9a33309a645c5a4fa9df1b4858634ae596ccc2aee5e`. These contracts likely contain malicious code designed to exploit the victim.

2.  **Interaction with Victim Contract:** The attacker interacts with the victim contract `0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4` using the following functions:
    - `execTransaction`: Transactions like `0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882` call this function on the victim. This function likely executes arbitrary transactions within the context of the victim contract, potentially allowing the attacker to modify its state or transfer assets.
    - `sweepETH`: Transactions like `0xb61413c495fdad6114a7aa863a00b2e3c28945979a10885b12b30316ea9f072c` call this function on the victim. This function is used to drain ETH from the victim contract.
    - `sweepERC20`: Transactions like `0x25800d105db4f21908d646a7a3db849343737c5fba0bc5701f782bf0e75217c9`, `0xbcf316f5835362b7f1586215173cc8b294f5499c60c029a3de6318bf25ca7b20`, `0xa284a1bc4c7e0379c924c73fcea1067068635507254b03ebbbd3f4e222c1fae0`, and `0x847b8403e8a4816a4de1e63db321705cdb6f998fb01ab58f653b863fda988647` call this function on the victim. This function is used to drain ERC20 tokens from the victim contract.

3.  **Fund Diversion:** After draining funds from the victim contract, the attacker transfers them to other addresses, potentially exchanges, to obfuscate the flow of funds.

4.  **Possible Rugpull:** The `workMyDirefulOwner` function calls to various addresses suggest the attacker might be transferring ownership or control of the deployed contracts, potentially as part of a rugpull scheme. The direct ETH transfers to the attacker address (e.g., in `0x484fa1a72d09dac97bd6458f779c0660962df852cc7cace51f1f905152881330`) further support this.

The combination of contract creation, interaction with the proxy contract using `execTransaction`, `sweepETH`, and `sweepERC20`, and the potential transfer of ownership suggests a coordinated attack aimed at draining funds from the victim contract, possibly as part of a rugpull scheme. The vulnerabilities in the proxy contract, particularly the lack of a withdrawal function and the use of assembly, likely facilitated the exploit.
