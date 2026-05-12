# Medusa-cuevm
The integration of CuEVM to Medusa 1.2.1. Beyond medusa `assertion` bug type, it supports more common bug type (Integer Overflow, Leaking Ether, Reentrancy) with the oracles written inside CuEVM. 

Extra features:
- Source line mapping to report bugs in solidity line number. Achieved by our [solc-json-parser](https://github.com/sbip-sg/solc-json-parser)
- Simple false positve reduction by pattern matching in solidity source.
- Extra flags for configuring `gpuWorkers`, `cpuWorkers`, `callSequenceLength`, `skipSolcInstall`, `etherscanJsonFile`. 

>The most important flags are cpu workers (> CPU 8 threads) and gpu workers (> 32768 GPU threads, depending on GPU memory).

`callSequenceLength` is the maximum transaction sequence length (how many transactions before the state reset). Higher `callSequenceLength` can discover bugs that requires multiple transactions to trigger at the cost of extra GPU memory. It is recommended to be at `8-10`.

The tool is dependent on CuEVM library, to build it you first need to build CuEVM and use the `./scripts/build.sh` with appropriate `CUEVM_HOME` set. For example: 
> CUEVM_HOME=/data/CuEVM ./scripts/build.sh`

Below is the original README file.

---
# medusa

`medusa` is a cross-platform [go-ethereum](https://github.com/ethereum/go-ethereum/)-based smart contract fuzzer inspired by [Echidna](https://github.com/crytic/echidna).
It provides parallelized fuzz testing of smart contracts through CLI, or its Go API that allows custom user-extended testing methodology.

**Disclaimer**: The Go-level testing API is still **under development** and is subject to breaking changes.

## Features

`medusa` provides support for:

- ✔️**Parallel fuzzing and testing** methodologies across multiple workers (threads)
- ✔️**Assertion and property testing**: built-in support for writing basic Solidity property tests and assertion tests
- ✔️**Mutational value generation**: fed by compilation and runtime values.
- ✔️**Coverage collecting**: Coverage increasing call sequences are stored in the corpus
- ✔️**Coverage guided fuzzing**: Coverage increasing call sequences from the corpus are mutated to further guide the fuzzing campaign
- ✔️**Extensible low-level testing API** through events and hooks provided throughout the fuzzer, workers, and test chains.
- ❌ **Extensible high-level testing API** allowing for the addition of per-contract or global post call/event property tests with minimal effort.

## Documentation

To learn more about how to install and use `medusa`, please refer to our [documentation](./docs/src/SUMMARY.md).

For a better viewing experience, we recommend you install [mdbook](https://rust-lang.github.io/mdBook/guide/installation.html)
and then running the following steps from medusa's source directory:

```bash
cd docs
mdbook serve
```

## Install

Run the following command to install the latest version of `medusa`:

```shell

go install github.com/crytic/medusa@latest
```

For more information on building from source, using package managers, or obtaining binaries for Windows and Linux,
please refer to the [installation guide](./docs/src/getting_started/installation.md).

## Contributing

For information about how to contribute to this project, check out the [CONTRIBUTING](./CONTRIBUTING.md) guidelines.

## License

`medusa` is licensed and distributed under the [AGPLv3](./LICENSE).
