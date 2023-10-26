This folder contains end-to-end tests for getting Algorand's blockchain information with the `evm t8n` command.

- `contracts` contains the Solidity contract `AlgorandInfo.sol`, which calls into the Algorand precompiled contract at address `0xff` to get the blockchain information. The contract can be compiled into EVM bytecode with:

  ```
  solc AlgorandInfo.sol --bin --evm-version london
  ```

- `txs` contains the signed Ethereum transactions to run with `evm t8n`. Inside a subfolder, run
  ```
  evm t8n --state.chainid 12345 --output.basedir out --state.fork London
  ```
  Result of the execution is in `out/result.json`.
