package fuzzing

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crytic/medusa-geth/crypto"

	"github.com/crytic/medusa/fuzzing/executiontracer"
	"github.com/crytic/medusa/fuzzing/reverts"

	"github.com/crytic/medusa/fuzzing/coverage"
	"github.com/crytic/medusa/logging"
	"github.com/crytic/medusa/logging/colors"
	"github.com/rs/zerolog"

	"github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/utils/randomutils"

	"github.com/crytic/medusa-geth/accounts/abi"
	"github.com/crytic/medusa-geth/common"

	// ethstate "github.com/ethereum/go-ethereum/core/state"

	// Change the import from ethereum/go-ethereum to crytic/medusa-geth
	ethstate "github.com/crytic/medusa-geth/core/state"
	// "github.com/ethereum/go-ethereum/core/types"

	"unsafe"

	"encoding/hex"
	"encoding/json"

	"github.com/crytic/medusa/chain"
	compilationTypes "github.com/crytic/medusa/compilation/types"
	"github.com/crytic/medusa/fuzzing/config"
	fuzzerTypes "github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/fuzzing/corpus"
	fuzzingutils "github.com/crytic/medusa/fuzzing/utils"
	"github.com/crytic/medusa/fuzzing/valuegeneration"
	"github.com/crytic/medusa/utils"

	// "github.com/ethereum/go-ethereum/accounts/abi"
	// "github.com/ethereum/go-ethereum/common"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

/*
#cgo CFLAGS: -I${SRCDIR}/../../CuEVM-internal  -I${SRCDIR}/../../CuEVM-internal/CuEVM/include
#cgo LDFLAGS: -L${SRCDIR}/../../CuEVM-internal/build -lcuevm_go -Wl,-rpath,${SRCDIR}/../../CuEVM-internal/build
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

// Only declare the functions that are actually implemented
int run_interpreter_go(const char* json_input, uint32_t skip_trace_parsing, uint32_t copy_state_data,
                       uint32_t reuse_state_data);

					   // Define C-compatible structures that can be shared with Go
// Define C-compatible structures that can be shared with Go
typedef struct {
    uint8_t* data;  // Pointer to the return data
    uint32_t length;  // Length of the return data
} ReturnDataEntry;

typedef struct {
    char** addresses;  // Array of contract addresses as strings
    uint32_t num_addresses;  // Number of addresses

    uint64_t** branch_coverage;  // Array of branch coverage arrays
    uint32_t* branch_coverage_lengths;  // Length of each branch coverage array
} CoverageDataEntry;

typedef struct {
    ReturnDataEntry* return_data;  // Array of return data entries
    uint32_t num_return_data;  // Number of7 return data entries
    CoverageDataEntry* coverage;  // Array of coverage data entries
    uint32_t num_coverage;  // Number of coverage entries
    uint8_t* error_codes;
} GPUExecutionResultC;

// Updated function declaration with reuse_state_data parameter
GPUExecutionResultC* process_batch_transactions(const unsigned char* fromAddr, const unsigned char* toAddr, const unsigned char* values,
                               const unsigned char* callData, int callDataLen, const uint32_t* dataOffsets,
                               int dataOffsetsLen, const uint32_t* dataSizes, int dataSizesLen, int txCount);

// Updated function declaration with reset_state parameter
int process_json_state_gpu(const char* json_state, uint32_t num_instances);

// Function to return results to Go
// Function to get GPU execution results
GPUExecutionResultC* get_gpu_execution_results();

// Function to free GPU execution results
void free_gpu_execution_results(GPUExecutionResultC* result);
*/
import "C"

// Fuzzer represents an Ethereum smart contract fuzzing provider.
type Fuzzer struct {
	// ctx is the main context used by the fuzzer.
	ctx context.Context
	// ctxCancelFunc describes a function which can be used to cancel the fuzzing operations the main ctx tracks.
	// Cancelling ctx does _not_ guarantee that all operations will terminate.
	ctxCancelFunc context.CancelFunc

	// emergencyCtx is the context that is used by the fuzzer to react to OS-level interrupts (e.g. SIGINT) or errors.
	emergencyCtx context.Context
	// emergencyCtxCancelFunc describes a function which can be used to cancel the fuzzing operations due to an OS-level
	// interrupt or an error. Cancelling emergencyCtx will guarantee that all operations will terminate.
	emergencyCtxCancelFunc context.CancelFunc

	// config describes the project configuration which the fuzzing is targeting.
	config config.ProjectConfig
	// senders describes a set of account addresses used to send state changing calls in fuzzing campaigns.
	senders []common.Address
	// deployer describes an account address used to deploy contracts in fuzzing campaigns.
	deployer common.Address

	// compilations describes all compilations added as targets.
	compilations []compilationTypes.Compilation
	// contractDefinitions defines targets to be fuzzed once their deployment is detected. They are derived from
	// compilations.
	contractDefinitions fuzzerTypes.Contracts
	// slitherResults holds the results obtained from slither. At the moment we do not have use for storing this in the
	// Fuzzer but down the line we can use slither for other capabilities that may require storage of the results.
	slitherResults *compilationTypes.SlitherResults

	// baseValueSet represents a valuegeneration.ValueSet containing input values for our fuzz tests.
	baseValueSet *valuegeneration.ValueSet

	// workers represents the work threads created by this Fuzzer when Start invokes a fuzz operation.
	workers []*FuzzerWorker
	// metrics represents the metrics for the fuzzing campaign.
	metrics *FuzzerMetrics
	// corpus stores a list of transaction sequences that can be used for coverage-guided fuzzing
	corpus *corpus.Corpus

	// revertReporter tracks per-function reversion metrics, if enabled
	revertReporter *reverts.RevertReporter

	// randomProvider describes the provider used to generate random values in the Fuzzer. All other random providers
	// used by the Fuzzer's subcomponents are derived from this one.
	randomProvider *rand.Rand

	// testCases contains every TestCase registered with the Fuzzer.
	testCases []TestCase
	// testCasesLock provides thread-synchronization to avoid race conditions when accessing or updating test cases.
	testCasesLock sync.Mutex
	// testCasesFinished describes test cases already reported as having been finalized.
	testCasesFinished map[string]TestCase

	// Events describes the event system for the Fuzzer.
	Events FuzzerEvents

	// Hooks describes the replaceable functions used by the Fuzzer.
	Hooks FuzzerHooks

	// logger describes the Fuzzer's log object that can be used to log important events
	logger *logging.Logger

	// lastPCsLogMsg records the last time we logged total PCs hit.
	// It takes a decent amount of time to calculate, so we only log once a minute,
	// and only when debug logging is enabled.
	lastPCsLogMsg time.Time

	// contractAddressToCodeHash maps contract addresses to their runtime bytecode hashes for quick lookup
	contractAddressToCodeHash map[common.Address]common.Hash
	// CuEVM debug: for directly calling in fuzzing loop
	property_test_provider     *PropertyTestCaseProvider
	assertion_test_provider    *AssertionTestCaseProvider
	optimization_test_provider *OptimizationTestCaseProvider
}

// Amount of time between "total PCs hit" log messages. This message is only output when debug logging is enabled.
const timeBetweenPCsLogMsgs = time.Minute

// NewFuzzer returns an instance of a new Fuzzer provided a project configuration, or an error if one is encountered
// while initializing the code.
func NewFuzzer(config config.ProjectConfig) (*Fuzzer, error) {
	// Disable colors if requested
	if config.Logging.NoColor {
		colors.DisableColor()
	}

	// Create the global logger and add stdout as an unstructured output stream
	// Note that we are not using the project config's log level because we have not validated it yet
	logging.GlobalLogger = logging.NewLogger(config.Logging.Level)
	logging.GlobalLogger.AddWriter(os.Stdout, logging.UNSTRUCTURED, !config.Logging.NoColor)

	// If the log directory is a non-empty string, create a file for unstructured, un-colorized file logging
	if config.Logging.LogDirectory != "" {
		// Filename will be the "log-current_unix_timestamp.log"
		filename := "log-" + strconv.FormatInt(time.Now().Unix(), 10) + ".log"
		// Create the file
		file, err := utils.CreateFile(config.Logging.LogDirectory, filename)
		if err != nil {
			logging.GlobalLogger.Error("Failed to create log file", err)
			return nil, err
		}
		logging.GlobalLogger.AddWriter(file, logging.UNSTRUCTURED, false)
	}

	// Validate our provided config
	err := config.Validate()
	if err != nil {
		logging.GlobalLogger.Error("Invalid configuration", err)
		return nil, err
	}

	// Update the log level of the global logger now
	logging.GlobalLogger.SetLevel(config.Logging.Level)

	// Get the fuzzer's custom sub-logger
	logger := logging.GlobalLogger.NewSubLogger("module", "fuzzer")

	// Parse the senders addresses from our account config.
	senders, err := utils.HexStringsToAddresses(config.Fuzzing.SenderAddresses)
	if err != nil {
		logger.Error("Invalid sender address(es)", err)
		return nil, err
	}

	// Parse the deployer address from our account config
	deployer, err := utils.HexStringToAddress(config.Fuzzing.DeployerAddress)
	if err != nil {
		logger.Error("Invalid deployer address", err)
		return nil, err
	}

	// Create the revert reporter
	revertReporter, err := reverts.NewRevertReporter(config.Fuzzing.RevertReporterEnabled, config.Fuzzing.CorpusDirectory)
	if err != nil {
		logger.Error("Failed to create revert reporter", err)
		return nil, err
	}

	// Create and return our fuzzing instance.
	fuzzer := &Fuzzer{
		config:                    config,
		senders:                   senders,
		deployer:                  deployer,
		baseValueSet:              valuegeneration.NewValueSet(),
		contractDefinitions:       make(fuzzerTypes.Contracts, 0),
		testCases:                 make([]TestCase, 0),
		testCasesFinished:         make(map[string]TestCase),
		contractAddressToCodeHash: make(map[common.Address]common.Hash),
		revertReporter:            revertReporter,
		Hooks: FuzzerHooks{
			NewCallSequenceGeneratorConfigFunc: defaultCallSequenceGeneratorConfigFunc,
			NewShrinkingValueMutatorFunc:       defaultShrinkingValueMutatorFunc,
			ChainSetupFunc:                     chainSetupFromCompilations,
			CallSequenceTestFuncs:              make([]CallSequenceTestFunc, 0),
		},
		logger: logger,
	}

	// Add our sender and deployer addresses to the base value set for the value generator, so they will be used as
	// address arguments in fuzzing campaigns.
	fuzzer.baseValueSet.AddAddress(fuzzer.deployer)
	for _, sender := range fuzzer.senders {
		fuzzer.baseValueSet.AddAddress(sender)
	}

	// If we have a compilation config
	if fuzzer.config.Compilation != nil {
		// Compile the targets specified in the compilation config
		fuzzer.logger.Info("Compiling targets with ", colors.Bold, fuzzer.config.Compilation.Platform, colors.Reset)
		start := time.Now()
		compilations, _, err := (*fuzzer.config.Compilation).Compile()
		if err != nil {
			fuzzer.logger.Error("Failed to compile target", err)
			return nil, err
		}
		fuzzer.logger.Info("Finished compiling targets in ", time.Since(start).Round(time.Second))

		// Add our compilation targets
		fuzzer.AddCompilationTargets(compilations)
	}

	// Provide any custom errors in the compiled artifacts' ABIs to the revert reporter now
	fuzzer.revertReporter.AddCustomErrors(fuzzer.contractDefinitions)

	// Register any default providers if specified.
	if fuzzer.config.Fuzzing.Testing.PropertyTesting.Enabled {
		fuzzer.property_test_provider = attachPropertyTestCaseProvider(fuzzer)
	}
	if fuzzer.config.Fuzzing.Testing.AssertionTesting.Enabled {
		fuzzer.assertion_test_provider = attachAssertionTestCaseProvider(fuzzer)
	}
	if fuzzer.config.Fuzzing.Testing.OptimizationTesting.Enabled {
		fuzzer.optimization_test_provider = attachOptimizationTestCaseProvider(fuzzer)
	}
	return fuzzer, nil
}

// ContractDefinitions exposes the contract definitions registered with the Fuzzer.
func (f *Fuzzer) ContractDefinitions() fuzzerTypes.Contracts {
	return slices.Clone(f.contractDefinitions)
}

// Config exposes the underlying project configuration provided to the Fuzzer.
func (f *Fuzzer) Config() config.ProjectConfig {
	return f.config
}

// BaseValueSet exposes the underlying value set provided to the Fuzzer value generators to aid in generation
// (e.g. for use in mutation operations).
func (f *Fuzzer) BaseValueSet() *valuegeneration.ValueSet {
	return f.baseValueSet
}

// SenderAddresses exposes the account addresses from which state changing fuzzed transactions will be sent by a
// FuzzerWorker.
func (f *Fuzzer) SenderAddresses() []common.Address {
	return f.senders
}

// DeployerAddress exposes the account address from which contracts will be deployed by a FuzzerWorker.
func (f *Fuzzer) DeployerAddress() common.Address {
	return f.deployer
}

// TestCases exposes the underlying tests run during the fuzzing campaign.
func (f *Fuzzer) TestCases() []TestCase {
	return f.testCases
}

// TestCasesWithStatus exposes the underlying tests with the provided status.
func (f *Fuzzer) TestCasesWithStatus(status TestCaseStatus) []TestCase {
	// Acquire a thread lock to avoid race conditions
	f.testCasesLock.Lock()
	defer f.testCasesLock.Unlock()

	// Collect all test cases with matching statuses.
	return utils.SliceWhere(f.testCases, func(t TestCase) bool {
		return t.Status() == status
	})
}

// RegisterTestCase registers a new TestCase with the Fuzzer.
func (f *Fuzzer) RegisterTestCase(testCase TestCase) {
	// Acquire a thread lock to avoid race conditions
	f.testCasesLock.Lock()
	defer f.testCasesLock.Unlock()

	// Display what is being tested
	f.logger.Info(testCase.LogMessage().Elements()...)

	// Append our test case to our list
	f.testCases = append(f.testCases, testCase)
}

// ReportTestCaseFinished is used to report a TestCase status as finalized to the Fuzzer.
func (f *Fuzzer) ReportTestCaseFinished(testCase TestCase) {
	// Acquire a thread lock to avoid race conditions
	f.testCasesLock.Lock()
	defer f.testCasesLock.Unlock()

	// If we already reported this test case as finished, stop
	if _, alreadyExists := f.testCasesFinished[testCase.ID()]; alreadyExists {
		return
	}

	// Otherwise now mark the test case as finished.
	f.testCasesFinished[testCase.ID()] = testCase

	// We only log here if we're not configured to stop on the first test failure. This is because the fuzzer prints
	// results on exit, so we avoid duplicate messages.
	if !f.config.Fuzzing.Testing.StopOnFailedTest {
		f.logger.Info(testCase.LogMessage().Elements()...)
	}

	// If the config specifies, we stop after the first failed test reported.
	if testCase.Status() == TestCaseStatusFailed && f.config.Fuzzing.Testing.StopOnFailedTest {
		f.Stop()
	}
}

// AddCompilationTargets takes a compilation and updates the Fuzzer state with additional Fuzzer.ContractDefinitions
// definitions and Fuzzer.BaseValueSet values.
func (f *Fuzzer) AddCompilationTargets(compilations []compilationTypes.Compilation) {
	var seedFromAST bool

	// No need to handle the error here since having compilation artifacts implies that we used a supported
	// platform configuration
	platformConfig, _ := f.config.Compilation.GetPlatformConfig()

	// Retrieve the compilation target for slither
	target := platformConfig.GetTarget()

	// Run slither and handle errors
	slitherResults, err := f.config.Slither.RunSlither(target)
	if err != nil || slitherResults == nil {
		if err != nil {
			f.logger.Warn("Failed to run slither", err)
		}
		seedFromAST = true
	}

	// If we have results and there were no errors, we will seed the value set using the slither results
	if !seedFromAST {
		f.slitherResults = slitherResults
		// Seed our base value set with the constants extracted by Slither
		f.baseValueSet.SeedFromSlither(slitherResults)
	}

	// Capture all the contract definitions, functions, and cache the source code
	for i := 0; i < len(compilations); i++ {
		// Add our compilation to the list and get a reference to it.
		f.compilations = append(f.compilations, compilations[i])
		compilation := &f.compilations[len(f.compilations)-1]

		// Loop for each source
		for sourcePath, source := range compilation.SourcePathToArtifact {
			// Seed from the contract's AST if we did not use slither or failed to do so
			if seedFromAST {
				// Seed our base value set from every source's AST
				f.baseValueSet.SeedFromAst(source.Ast)
			}

			// Loop for every contract and register it in our contract definitions
			for contractName := range source.Contracts {
				contract := source.Contracts[contractName]

				// Skip interfaces.
				if contract.Kind == compilationTypes.ContractKindInterface {
					continue
				}

				contractDefinition := fuzzerTypes.NewContract(contractName, sourcePath, &contract, compilation)

				// Sort available methods by type
				assertionTestMethods, propertyTestMethods, optimizationTestMethods := fuzzingutils.BinTestByType(&contract,
					f.config.Fuzzing.Testing.PropertyTesting.TestPrefixes,
					f.config.Fuzzing.Testing.OptimizationTesting.TestPrefixes,
					f.config.Fuzzing.Testing.TestViewMethods)
				contractDefinition.AssertionTestMethods = assertionTestMethods
				contractDefinition.PropertyTestMethods = propertyTestMethods
				contractDefinition.OptimizationTestMethods = optimizationTestMethods

				// Filter and record methods available for assertion testing. Property and optimization tests are always run.
				if len(f.config.Fuzzing.Testing.TargetFunctionSignatures) > 0 {
					// Only consider methods that are in the target methods list
					contractDefinition = contractDefinition.WithTargetedAssertionMethods(f.config.Fuzzing.Testing.TargetFunctionSignatures)
				}
				if len(f.config.Fuzzing.Testing.ExcludeFunctionSignatures) > 0 {
					// Consider all methods except those in the exclude methods list
					contractDefinition = contractDefinition.WithExcludedAssertionMethods(f.config.Fuzzing.Testing.ExcludeFunctionSignatures)
				}

				f.contractDefinitions = append(f.contractDefinitions, contractDefinition)
			}
		}

		// Cache all of our source code if it hasn't been already.
		err := compilation.CacheSourceCode()
		if err != nil {
			f.logger.Warn("Failed to cache compilation source file data", err)
		}
	}
}

// createTestChain creates a test chain with the account balance allocations specified by the config.
func (f *Fuzzer) createTestChain() (*chain.TestChain, error) {
	// Create our genesis allocations.
	// NOTE: Sharing GenesisAlloc between chains will result in some accounts not being funded for some reason.
	genesisAlloc := make(types.GenesisAlloc)

	// Fund all of our sender addresses in the genesis block
	initBalance := new(big.Int).Div(abi.MaxInt256, big.NewInt(2)) // TODO: make this configurable
	for _, sender := range f.senders {
		genesisAlloc[sender] = types.Account{
			Balance: initBalance,
		}
	}

	// Fund our deployer address in the genesis block
	genesisAlloc[f.deployer] = types.Account{
		Balance: initBalance,
	}

	// Identify which contracts need to be predeployed to a deterministic address by iterating across the mapping
	contractAddressOverrides := make(map[common.Hash]common.Address, len(f.config.Fuzzing.PredeployedContracts))
	for contractName, addrStr := range f.config.Fuzzing.PredeployedContracts {
		found := false
		// Try to find the associated compilation artifact
		for _, contract := range f.contractDefinitions {
			if contract.Name() == contractName {
				// Hash the init bytecode (so that it can be easily identified in the EVM) and map it to the
				// requested address
				initBytecodeHash := crypto.Keccak256Hash(contract.CompiledContract().InitBytecode)
				contractAddr, err := utils.HexStringToAddress(addrStr)
				if err != nil {
					return nil, fmt.Errorf("invalid address provided for a predeployed contract: %v", contract.Name())
				}
				contractAddressOverrides[initBytecodeHash] = contractAddr
				found = true
				break
			}
		}

		// Throw an error if the contract specified in the config is not found
		if !found {
			return nil, fmt.Errorf("%v was specified in the predeployed contracts but was not found in the compilation artifacts", contractName)
		}
	}

	// Update the test chain config with the contract address overrides
	f.config.Fuzzing.TestChainConfig.ContractAddressOverrides = contractAddressOverrides

	// Create our test chain with our basic allocations and passed medusa's chain configuration
	testChain, err := chain.NewTestChain(f.ctx, genesisAlloc, &f.config.Fuzzing.TestChainConfig)

	// Set our block gas limit
	testChain.BlockGasLimit = f.config.Fuzzing.BlockGasLimit
	return testChain, err
}

// chainSetupFromCompilations is a TestChainSetupFunc which sets up the base test chain state by deploying
// all compiled contract definitions. This includes any successful compilations as a result of the Fuzzer.config
// definitions, as well as those added by Fuzzer.AddCompilationTargets. The contract deployment order is defined by
// the Fuzzer.config.
func chainSetupFromCompilations(fuzzer *Fuzzer, testChain *chain.TestChain) (*executiontracer.ExecutionTrace, error) {
	// Verify that target contracts is not empty. If it's empty, but we only have one contract definition,
	// we can infer the target contracts. Otherwise, we report an error.
	if len(fuzzer.config.Fuzzing.TargetContracts) == 0 {
		var found bool
		for _, contract := range fuzzer.contractDefinitions {
			// If only one contract is defined, we can infer the target contract by filtering interfaces/libraries.
			if contract.CompiledContract().Kind == compilationTypes.ContractKindContract {
				if !found {
					fuzzer.config.Fuzzing.TargetContracts = []string{contract.Name()}
					found = true
				} else {
					// TODO list options for the user to choose from
					return nil, fmt.Errorf("specify target contract(s)")
				}
			}
		}
	}

	// Concatenate the predeployed contracts and target contracts
	// Ordering is important here (predeploys _then_ targets) so that you can have the same contract in both lists
	// while still being able to use the contract address overrides
	contractsToDeploy := make([]string, 0)
	balances := make([]*config.ContractBalance, 0)

	for contractName := range fuzzer.config.Fuzzing.PredeployedContracts {
		contractsToDeploy = append(contractsToDeploy, contractName)
		// Preserve index of target contract balances
		balances = append(balances, &config.ContractBalance{Int: *big.NewInt(0)})
	}
	contractsToDeploy = append(contractsToDeploy, fuzzer.config.Fuzzing.TargetContracts...)
	balances = append(balances, fuzzer.config.Fuzzing.TargetContractsBalances...)

	deployedContractAddr := make(map[string]common.Address)
	// Loop for all contracts to deploy
	for i, contractName := range contractsToDeploy {
		// Look for a contract in our compiled contract definitions that matches this one
		found := false
		for _, contract := range fuzzer.contractDefinitions {
			// If we found a contract definition that matches this definition by name, try to deploy it
			if contract.Name() == contractName {
				testChain.CompiledContracts[contractName] = contract.CompiledContract()
				// Concatenate constructor arguments, if necessary
				args := make([]any, 0)
				if len(contract.CompiledContract().Abi.Constructor.Inputs) > 0 {
					// If the contract is a predeployed contract, throw an error because they do not accept constructor
					// args.
					if _, ok := fuzzer.config.Fuzzing.PredeployedContracts[contractName]; ok {
						return nil, fmt.Errorf("predeployed contracts cannot accept constructor arguments")
					}
					jsonArgs, ok := fuzzer.config.Fuzzing.ConstructorArgs[contractName]
					if !ok {
						return nil, fmt.Errorf("constructor arguments for contract %s not provided", contractName)
					}
					decoded, err := valuegeneration.DecodeJSONArgumentsFromMap(contract.CompiledContract().Abi.Constructor.Inputs,
						jsonArgs, deployedContractAddr)
					if err != nil {
						return nil, err
					}
					args = decoded
				}

				// Construct our deployment message/tx data field
				msgData, err := contract.CompiledContract().GetDeploymentMessageData(args)
				if err != nil {
					return nil, fmt.Errorf("initial contract deployment failed for contract \"%v\", error: %v", contractName, err)
				}

				// If our project config has a non-zero balance for this target contract, retrieve it
				contractBalance := big.NewInt(0)
				if len(balances) > i {
					contractBalance = new(big.Int).Set(&balances[i].Int)
				}

				// Create a message to represent our contract deployment (we let deployments consume the whole block
				// gas limit rather than use tx gas limit)
				msg := calls.NewCallMessage(fuzzer.deployer, nil, 0, contractBalance, fuzzer.config.Fuzzing.BlockGasLimit, nil, nil, nil, msgData)
				msg.FillFromTestChainProperties(testChain)

				// Create a new pending block we'll commit to chain
				block, err := testChain.PendingBlockCreate()
				if err != nil {
					return nil, err
				}

				// Add our transaction to the block
				err = testChain.PendingBlockAddTx(msg.ToCoreMessage())
				if err != nil {
					return nil, err
				}

				// Commit the pending block to the chain, so it becomes the new head.
				err = testChain.PendingBlockCommit()
				if err != nil {
					return nil, err
				}

				// Ensure our transaction succeeded and, if it did not, attach an execution trace to it and re-run it.
				// The execution trace will be returned so that it can be provided to the user for debugging
				if block.MessageResults[0].Receipt.Status != types.ReceiptStatusSuccessful {
					// Create a call sequence element to represent the failed contract deployment tx
					cse := calls.NewCallSequenceElement(nil, msg, 0, 0)
					cse.ChainReference = &calls.CallSequenceElementChainReference{
						Block:            block,
						TransactionIndex: len(block.Messages) - 1,
					}
					// Revert to one block before and re-run the failed contract deployment tx.
					// This should be one index before the current head block index.
					// We should be able to attach an execution trace; however, if it fails, we provide the ExecutionResult at a minimum.
					err = testChain.RevertToBlockIndex(uint64(len(testChain.CommittedBlocks()) - 1))
					if err != nil {
						return nil, fmt.Errorf("failed to reset to genesis block: %v", err)
					} else {
						_, err = calls.ExecuteCallSequenceWithExecutionTracer(testChain, fuzzer.contractDefinitions, []*calls.CallSequenceElement{cse}, config.VeryVeryVerbose)
						if err != nil {
							return nil, fmt.Errorf("deploying %s returned a failed status: %v", contractName, block.MessageResults[0].ExecutionResult.Err)
						}
					}

					// Return the execution error and the execution trace, if possible.
					return cse.ExecutionTrace, fmt.Errorf("deploying %s returned a failed status: %v", contractName, block.MessageResults[0].ExecutionResult.Err)
				}

				// Record our deployed contract so the next config-specified constructor args can reference this
				// contract by name.
				deployedContractAddr[contractName] = block.MessageResults[0].Receipt.ContractAddress

				// Flag that we found a matching compiled contract definition and deployed it, then exit out of this
				// inner loop to process the next contract to deploy in the outer loop.
				found = true
				break
			}
		}

		// If we did not find a contract corresponding to this item in the deployment order, we throw an error.
		if !found {
			return nil, fmt.Errorf("%v was specified in the target contracts but was not found in the compilation artifacts", contractName)
		}
	}
	return nil, nil
}

// defaultCallSequenceGeneratorConfigFunc is a NewCallSequenceGeneratorConfigFunc which creates a
// CallSequenceGeneratorConfig with a default configuration. Returns the config or an error, if one occurs.
func defaultCallSequenceGeneratorConfigFunc(fuzzer *Fuzzer, valueSet *valuegeneration.ValueSet, randomProvider *rand.Rand) (*CallSequenceGeneratorConfig, error) {
	// Create the value generator and mutator for the worker.
	mutationalGeneratorConfig := &valuegeneration.MutationalValueGeneratorConfig{
		MinMutationRounds:               0,
		MaxMutationRounds:               1,
		GenerateRandomAddressBias:       0.05,
		GenerateRandomIntegerBias:       0.5,
		GenerateRandomStringBias:        0.05,
		GenerateRandomBytesBias:         0.05,
		MutateAddressProbability:        0.1,
		MutateArrayStructureProbability: 0.1,
		MutateBoolProbability:           0.1,
		MutateBytesProbability:          0.1,
		MutateBytesGenerateNewBias:      0.45,
		MutateFixedBytesProbability:     0.1,
		MutateStringProbability:         0.1,
		MutateStringGenerateNewBias:     0.7,
		MutateIntegerProbability:        0.1,
		MutateIntegerGenerateNewBias:    0.5,
		RandomValueGeneratorConfig: &valuegeneration.RandomValueGeneratorConfig{
			GenerateRandomArrayMinSize:  0,
			GenerateRandomArrayMaxSize:  100,
			GenerateRandomBytesMinSize:  0,
			GenerateRandomBytesMaxSize:  100,
			GenerateRandomStringMinSize: 0,
			GenerateRandomStringMaxSize: 100,
		},
	}
	mutationalGenerator := valuegeneration.NewMutationalValueGenerator(mutationalGeneratorConfig, valueSet, randomProvider)

	// Create a sequence generator config which uses the created value generator.
	sequenceGenConfig := &CallSequenceGeneratorConfig{
		NewSequenceProbability:                   0.3,
		RandomUnmodifiedCorpusHeadWeight:         800,
		RandomUnmodifiedCorpusTailWeight:         100,
		RandomUnmodifiedSpliceAtRandomWeight:     200,
		RandomUnmodifiedInterleaveAtRandomWeight: 100,
		RandomMutatedCorpusHeadWeight:            80,
		RandomMutatedCorpusTailWeight:            10,
		RandomMutatedSpliceAtRandomWeight:        20,
		RandomMutatedInterleaveAtRandomWeight:    10,
		ValueGenerator:                           mutationalGenerator,
		ValueMutator:                             mutationalGenerator,
	}
	return sequenceGenConfig, nil
}

// defaultShrinkingValueMutatorFunc is a NewShrinkingValueMutatorFunc which creates value mutator to be used for
// shrinking purposes. Returns the value mutator or an error, if one occurs.
func defaultShrinkingValueMutatorFunc(fuzzer *Fuzzer, valueSet *valuegeneration.ValueSet, randomProvider *rand.Rand) (valuegeneration.ValueMutator, error) {
	// Create the shrinking value mutator for the worker.
	shrinkingValueMutatorConfig := &valuegeneration.ShrinkingValueMutatorConfig{
		ShrinkValueProbability: 0.1,
	}
	shrinkingValueMutator := valuegeneration.NewShrinkingValueMutator(shrinkingValueMutatorConfig, valueSet, randomProvider)
	return shrinkingValueMutator, nil
}

// spawnWorkersLoop is a method which spawns a config-defined amount of FuzzerWorker to carry out the fuzzing campaign.
// This function exits when Fuzzer.ctx is cancelled.
func (f *Fuzzer) spawnWorkersLoop(baseTestChain *chain.TestChain) error {
	// Initialize workers array
	f.workers = make([]*FuzzerWorker, f.config.Fuzzing.Workers)

	// Create all workers upfront
	for i := 0; i < f.config.Fuzzing.Workers; i++ {
		// Create a new worker for this fuzzing
		randomProvider := randomutils.ForkRandomProvider(f.randomProvider)
		worker, err := newFuzzerWorker(f, i, randomProvider)
		if err != nil {
			f.logger.Error("Failed to create worker", err)
			return err
		}

		f.workers[i] = worker

		// Publish an event indicating we created a worker
		err = f.Events.WorkerCreated.Publish(FuzzerWorkerCreatedEvent{Worker: worker})
		if err != nil {
			f.logger.Error("Failed to publish worker created event", err)
			return err
		}
	}
	loopCounter := 0
	// Main processing loop
	working := true
	for working && !utils.CheckContextDone(f.ctx) {
		// Step 1: Prepare data in parallel
		workersCancelled, err := f.prepareWorkersDataInParallel(baseTestChain)
		if err != nil {
			return err
		}
		if workersCancelled {
			working = false
			continue
		}

		// Step 2: Launch GPU kernel - focusing only on testNextCallSequence
		err = f.launchGPUKernel()
		if err != nil {
			return err
		}

		// Step 3: Process results in parallel
		workersCancelled, err = f.processWorkersResultsInParallel()
		if err != nil {
			return err
		}
		if workersCancelled {
			working = false
		}

		loopCounter++
		// if loopCounter == 2 {
		// 	working = false
		// }
		fmt.Printf("\n Medusa loop counter: %d\n", loopCounter)

	}
	// fmt.Println("Medusa Coverage after fuzzing")
	// fmt.Println(f.corpus.CoverageMaps().DebugString())
	// Clean up workers
	for i := 0; i < len(f.workers); i++ {
		worker := f.workers[i]
		if worker != nil {
			err := f.Events.WorkerDestroyed.Publish(FuzzerWorkerDestroyedEvent{Worker: worker})
			if err != nil {
				f.logger.Error("Failed to publish worker destroyed event", err)
			}
		}
	}

	return nil
}

// prepareWorkersDataInParallel handles all setup logic from run() in parallel
// Returns a boolean indicating if workers should be cancelled and an error if one occurred
func (f *Fuzzer) prepareWorkersDataInParallel(baseTestChain *chain.TestChain) (bool, error) {
	var wg sync.WaitGroup
	errChan := make(chan error, f.config.Fuzzing.Workers)
	cancelChan := make(chan bool, f.config.Fuzzing.Workers)

	for i := 0; i < len(f.workers); i++ {
		wg.Add(1)
		go func(workerIndex int) {
			defer wg.Done()

			worker := f.workers[workerIndex]
			if worker == nil {
				return
			}

			// Check for emergency context cancellation
			if utils.CheckContextDone(f.emergencyCtx) {
				cancelChan <- true
				return
			}

			// Handle main context cancellation - don't return yet, as we need to process shrink requests
			fuzzingComplete := false
			if utils.CheckContextDone(f.ctx) {
				fuzzingComplete = true
				err := worker.Events.TestingComplete.Publish(FuzzerWorkerTestingCompleteEvent{
					Worker: worker,
				})
				if err != nil {
					errChan <- fmt.Errorf("error returned by an event handler: %v", err)
					return
				}
			}

			// Process any pending shrink requests
			for _, shrinkCallSequenceRequest := range worker.shrinkCallSequenceRequests {
				fmt.Println("processing shrink call sequence request", shrinkCallSequenceRequest)
				if utils.CheckContextDone(f.emergencyCtx) {
					cancelChan <- true
					return
				}
				if worker.chain == nil {
					fmt.Println("worker.chain is nil, skipping shrink call sequence request")
					break
				}
				_, err := worker.shrinkCallSequence(shrinkCallSequenceRequest)
				if err != nil {
					errChan <- err
					return
				}
			}

			// Clear shrink requests now that they've been processed
			worker.shrinkCallSequenceRequests = nil

			// If fuzzing is complete, signal cancellation
			if fuzzingComplete {
				cancelChan <- true
				return
			}

			// Setup chain if this is the first run
			if worker.chain == nil {
				// fmt.Println("worker.chain is nil, setting up worker chain")
				var err error
				worker.chain, err = baseTestChain.Clone(func(initializedChain *chain.TestChain) error {
					// Subscribe our chain event handlers
					initializedChain.Events.ContractDeploymentAddedEventEmitter.Subscribe(worker.onChainContractDeploymentAddedEvent)
					initializedChain.Events.ContractDeploymentRemovedEventEmitter.Subscribe(worker.onChainContractDeploymentRemovedEvent)

					// If we have coverage-guided fuzzing enabled, create a tracer to collect coverage and connect it to the chain
					if f.config.Fuzzing.CoverageEnabled {
						worker.coverageTracer = coverage.NewCoverageTracer()
						initializedChain.AddTracer(worker.coverageTracer.NativeTracer(), true, false)
					}

					// Copy the labels from the base chain to the worker's chain
					initializedChain.Labels = maps.Clone(baseTestChain.Labels)

					// Emit an event indicating the worker has created its chain
					err := worker.Events.FuzzerWorkerChainCreated.Publish(FuzzerWorkerChainCreatedEvent{
						Worker: worker,
						Chain:  initializedChain,
					})
					// fmt.Println("error in fuzzer worker chain created clone", err)
					return err
				})

				if err != nil {
					errChan <- err
					return
				}

				// Emit an event indicating the worker has set up its chain
				err = worker.Events.FuzzerWorkerChainSetup.Publish(FuzzerWorkerChainSetupEvent{
					Worker: worker,
					Chain:  worker.chain,
				})
				if err != nil {
					errChan <- fmt.Errorf("error returned by an event handler: %v", err)
					return
				}

				// Increase our generation metric
				worker.workerMetrics().workerStartupCount.Add(worker.workerMetrics().workerStartupCount, big.NewInt(1))

				// Save the current block index as all contracts have been deployed at this point
				worker.testingBaseBlockIndex = uint64(len(worker.chain.CommittedBlocks()))

			} else {
				// If we already have a chain, revert to the base state
				err := worker.chain.RevertToBlockIndex(worker.testingBaseBlockIndex)
				if err != nil {
					errChan <- err
					return
				}
			}

			// Prepare execution data for GPU kernel
			worker.originalValueSet = worker.valueSet.Clone()

			// Initialize a new sequence within our sequence generator
			isNewSequence, err := worker.sequenceGenerator.InitializeNextSequence()
			if err != nil {
				errChan <- err
				return
			}
			worker.isNewSequence = isNewSequence

			// Prepare a fresh list for shrink requests
			worker.pendingShrinkRequests = make([]ShrinkCallSequenceRequest, 0)

			// Create execution check function for this worker
			worker.executionCheckFunc = func(currentlyExecutedSequence calls.CallSequence) (bool, error) {
				// Get the last call sequence element that was executed
				latestCallSequenceElement := currentlyExecutedSequence[len(currentlyExecutedSequence)-1]
				// Get the decoded return values and add it to the base value set
				// Don't throw an error since we care more about coverage than adding the return values to the base value set
				decodedReturnValues, err := latestCallSequenceElement.DecodedReturnValues()
				if decodedReturnValues != nil && err == nil {
					worker.valueSet.Add(decodedReturnValues)
				}

				// Check for updates to coverage and corpus.
				// If we detect coverage changes, add this sequence with weight as 1 + sequences tested (to avoid zero weights)
				err = f.corpus.CheckSequenceCoverageAndUpdate(currentlyExecutedSequence, worker.getNewCorpusCallSequenceWeight(), true)
				if err != nil {
					return true, err
				}

				// Loop through each test function, signal our worker tested a call, and collect any requests to shrink
				// this call sequence.
				for _, callSequenceTestFunc := range f.Hooks.CallSequenceTestFuncs {
					newShrinkRequests, err := callSequenceTestFunc(worker, currentlyExecutedSequence)
					if err != nil {
						return true, err
					}
					worker.pendingShrinkRequests = append(worker.pendingShrinkRequests, newShrinkRequests...)
				}

				// Update our metrics
				worker.workerMetrics().callsTested.Add(worker.workerMetrics().callsTested, big.NewInt(1))
				lastCallSequenceElement := currentlyExecutedSequence[len(currentlyExecutedSequence)-1]
				worker.workerMetrics().gasUsed.Add(worker.workerMetrics().gasUsed, new(big.Int).SetUint64(lastCallSequenceElement.ChainReference.Block.MessageResults[lastCallSequenceElement.ChainReference.TransactionIndex].Receipt.GasUsed))

				// If our fuzzer context or the emergency context is cancelled, exit out immediately without results.
				if utils.CheckContextDone(f.ctx) {
					return true, nil
				}

				// If we have shrink requests, it means we violated a test, so we quit at this point
				return len(worker.pendingShrinkRequests) > 0, nil
			}

			// NEW: Prepare the call sequence elements list for this worker
			worker.callSequenceElements = make([]*calls.CallSequenceElement, 0)
			// Track nonces for each sender address
			nonceMap := make(map[common.Address]uint64)

			// Populate the list with elements from the sequence generator
			for i := 0; ; i++ {
				element, err := worker.sequenceGenerator.PopSequenceElement()
				if err != nil {
					errChan <- err
					return
				}
				if element == nil {
					break
				}

				// Fix nonce if needed
				if element.Call != nil {
					sender := element.Call.From
					currentNonce, exists := nonceMap[sender]

					if exists && element.Call.Nonce <= currentNonce {
						// Update nonce if it's not greater than the current nonce for this sender
						element.Call.Nonce = currentNonce + 1
					}

					// Update the nonce map with the latest value
					nonceMap[sender] = element.Call.Nonce
				}

				worker.callSequenceElements = append(worker.callSequenceElements, element)
			}
			// print the call sequence elements
			// fmt.Println("callSequenceElements: ", worker.callSequenceElements)
			// Emit event indicating the worker is about to test a new call sequence
			err = worker.Events.CallSequenceTesting.Publish(FuzzerWorkerCallSequenceTestingEvent{
				Worker: worker,
			})
			if err != nil {
				errChan <- fmt.Errorf("error returned by an event handler: %v", err)
				return
			}
		}(i)
	}

	// Wait for all workers to finish preparation
	wg.Wait()
	close(errChan)
	close(cancelChan)

	// Check if there were any errors
	for err := range errChan {
		return false, err
	}

	// Check if any workers signaled cancellation
	for cancel := range cancelChan {
		if cancel {
			return true, nil
		}
	}

	return false, nil
}

// prepareAndProcessTransactionDataInGPU extracts transaction data from call sequence elements and sends it to the GPU
func (f *Fuzzer) runTransactionsGPU(callSequenceElements []*calls.CallSequenceElement) (*coverage.GPUExecutionResult, error) {
	fmt.Println("\nGo: Preparing transaction data in batch for GPU processing worker\n")

	// Count valid call elements first
	validCallCount := 0
	for _, element := range callSequenceElements {
		if element.Call != nil {
			validCallCount++
		}
	}

	if validCallCount == 0 {
		return nil, nil // Nothing to process
	}

	// Use fixed from and to addresses (32 bytes each)
	fromAddr := make([]byte, 32)
	toAddr := make([]byte, 32)

	// Use first valid call element for from/to addresses
	for _, element := range callSequenceElements {
		if element.Call != nil {
			// Copy from address (right-padded to 32 bytes)
			copy(fromAddr[12:], element.Call.From.Bytes()) // Ethereum addresses are 20 bytes

			// Copy to address (right-padded to 32 bytes)
			if element.Call.To != nil {
				copy(toAddr[12:], element.Call.To.Bytes())
			}
			break
		}
	}

	// Pre-allocate value array
	values := make([]byte, validCallCount*32) // 32 bytes for each uint256

	// For data we need two arrays - the data itself and offsets
	// First pass to calculate total data size
	totalDataSize := 0
	for _, element := range callSequenceElements {
		if element.Call != nil {
			totalDataSize += len(element.Call.Data)
		}
	}

	callData := make([]byte, totalDataSize)
	dataOffsets := make([]uint32, validCallCount)
	dataSizes := make([]uint32, validCallCount)

	// Fill arrays from call elements
	idx := 0
	dataOffset := 0
	for _, element := range callSequenceElements {
		if element.Call == nil {
			continue
		}

		call := element.Call

		// Copy value (big-endian)
		valueBytes := call.Value.Bytes()
		copy(values[idx*32+32-len(valueBytes):idx*32+32], valueBytes)

		// Handle call data
		if len(call.Data) > 0 {
			copy(callData[dataOffset:], call.Data)
			dataOffsets[idx] = uint32(dataOffset)
			dataSizes[idx] = uint32(len(call.Data))
			dataOffset += len(call.Data)
		}

		idx++
	}

	// Call C function with simplified arrays
	cResult := C.process_batch_transactions(
		(*C.uchar)(unsafe.Pointer(&fromAddr[0])),
		(*C.uchar)(unsafe.Pointer(&toAddr[0])),
		(*C.uchar)(unsafe.Pointer(&values[0])),
		(*C.uchar)(unsafe.Pointer(&callData[0])), C.int(len(callData)),
		(*C.uint)(unsafe.Pointer(&dataOffsets[0])), C.int(len(dataOffsets)),
		(*C.uint)(unsafe.Pointer(&dataSizes[0])), C.int(len(dataSizes)),
		C.int(validCallCount),
	)

	// Check if execution failed
	if cResult == nil {
		fmt.Println("GPU transaction processing failed")
		return nil, fmt.Errorf("GPU transaction processing failed")
	}

	// Ensure we free the C result when we're done with it
	defer C.free_gpu_execution_results(cResult)

	// Parse the C result into a Go structure
	result := &coverage.GPUExecutionResult{
		ReturnData: make([][]byte, int(cResult.num_return_data)),
		Coverage:   make([]coverage.GPUCoverage, int(cResult.num_coverage)),
		ErrorCodes: make([]uint8, int(cResult.num_return_data)),
	}

	// Process return data
	// returnDataSlice := unsafe.Slice(cResult.return_data, int(cResult.num_return_data))
	// for i := 0; i < int(cResult.num_return_data); i++ {
	// 	cData := returnDataSlice[i]
	// 	if cData.data != nil && cData.length > 0 {
	// 		// Create a Go slice that directly references the C data
	// 		dataSlice := C.GoBytes(unsafe.Pointer(cData.data), C.int(cData.length))
	// 		result.ReturnData[i] = dataSlice
	// 	} else {
	// 		result.ReturnData[i] = []byte{}
	// 	}
	// }

	// Process coverage data
	coverageSlice := unsafe.Slice(cResult.coverage, int(cResult.num_coverage))
	numCoverage := int(cResult.num_coverage)

	// Pre-allocate the result array
	result.Coverage = make([]coverage.GPUCoverage, numCoverage)

	// Create a wait group to wait for all goroutines
	var wg sync.WaitGroup

	// Determine number of workers based on available CPU cores
	numWorkers := runtime.NumCPU()
	if numWorkers > numCoverage {
		numWorkers = numCoverage
	}

	// Create a worker pool
	workChan := make(chan int, numCoverage)

	// Launch worker goroutines
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range workChan {
				cCov := coverageSlice[i]
				coverage := coverage.GPUCoverage{
					Addresses:       make([]string, int(cCov.num_addresses)),
					BranchCoverages: make([][]uint64, int(cCov.num_addresses)),
				}

				// Process addresses
				addressesSlice := unsafe.Slice(cCov.addresses, int(cCov.num_addresses))
				for j := 0; j < int(cCov.num_addresses); j++ {
					coverage.Addresses[j] = C.GoString(addressesSlice[j])

					// Process branch coverage for this address
					if j < int(cCov.num_addresses) {
						branchCovSlice := unsafe.Slice(cCov.branch_coverage, int(cCov.num_addresses))
						branchCovLengthsSlice := unsafe.Slice(cCov.branch_coverage_lengths, int(cCov.num_addresses))

						if branchCovSlice[j] != nil {
							length := branchCovLengthsSlice[j]
							// Directly create a slice of uint64 markers
							markers := make([]uint64, int(length))

							// Copy the 64-bit markers directly
							cMarkers := unsafe.Slice((*uint64)(unsafe.Pointer(branchCovSlice[j])), int(length))
							for k := 0; k < int(length); k++ {
								if cMarkers[k] != 0 { // Only include non-zero markers
									markers[k] = uint64(cMarkers[k])
								}
							}
							coverage.BranchCoverages[j] = markers
						}
					}
				}

				// Thread-safe assignment to result
				result.Coverage[i] = coverage
			}
		}()
	}

	// Send work to the workers
	for i := 0; i < numCoverage; i++ {
		workChan <- i
	}
	close(workChan)

	// Wait for all workers to finish
	wg.Wait()

	// Process success status
	if cResult.error_codes != nil && cResult.num_return_data > 0 {
		errorCodesSlice := unsafe.Slice(cResult.error_codes, int(cResult.num_return_data))
		errorCodesStr := make([]string, int(cResult.num_return_data))
		for i := 0; i < int(cResult.num_return_data); i++ {
			result.ErrorCodes[i] = uint8(errorCodesSlice[i])
			errorCodesStr[i] = fmt.Sprintf("%v", result.ErrorCodes[i])
		}
		fmt.Printf("Go: ErrorCodes = [%s]\n", strings.Join(errorCodesStr, ", "))
	} else {
		fmt.Println("Go: No success status data received from C.")
		// Fill with default false if needed, though it should match num_return_data
		for i := 0; i < len(result.ErrorCodes); i++ {
			result.ErrorCodes[i] = 0
		}
	}

	return result, nil
}

// prepareAndProcessChainStateInGPU extracts the chain state and block header information and sends it to the GPU
func (f *Fuzzer) prepareAndProcessChainStateInGPU(testChain *chain.TestChain) error {
	fmt.Println("Go: Preparing and processing chain state data in GPU")
	// Print all deployed contracts and their bytecode hashes
	fmt.Println("===== DEPLOYED CONTRACTS AND THEIR BYTECODE HASHES =====")
	worker := f.workers[0]
	if worker != nil && worker.deployedContracts != nil {
		fmt.Printf("Worker %d deployed contracts:\n", worker.workerIndex)
		for addr, contract := range worker.deployedContracts {
			// Check if we already have the hash in our map
			if codeHash, exists := f.contractAddressToCodeHash[addr]; exists {
				fmt.Printf("  Contract %s at %s - cached hash: %s\n",
					contract.Name(), addr.Hex(), codeHash.Hex())
				continue
			}

			// Get the bytecode from the chain state
			code := contract.CompiledContract().RuntimeBytecode
			// Calculate the hash using similar logic to getContractCoverageMapHash
			var codeHash common.Hash

			// For runtime bytecode, try to extract hash from metadata first
			metadata := compilationTypes.ExtractContractMetadata(code)
			if metadata != nil {
				metadataHash := metadata.ExtractBytecodeHash()
				if metadataHash != nil {
					codeHash = common.BytesToHash(metadataHash)
					// Save the hash to our map
					f.contractAddressToCodeHash[addr] = codeHash
					fmt.Printf("  Contract %s at %s - metadata hash: %s\n",
						contract.Name(), addr.Hex(), codeHash.Hex())
					continue
				}
			}
			// Fall back to hashing the stripped bytecode
			strippedCode := compilationTypes.RemoveContractMetadata(code)
			codeHash = crypto.Keccak256Hash(strippedCode)
			// Save the hash to our map
			f.contractAddressToCodeHash[addr] = codeHash
			fmt.Printf("  Contract %s at %s - bytecode hash: %s\n",
				contract.Name(), addr.Hex(), codeHash.Hex())
		}
		fmt.Println()
	}

	fmt.Println("========================================================")

	// codeCoverageLookupHash := getContractCoverageMapHash(code, isCreate)

	// Get the current state from the chain
	state := testChain.State()

	eth_state, ok := state.(*ethstate.StateDB)

	if state == nil || !ok {
		return fmt.Errorf("chain state is nil")
	}

	// Get raw state dump
	dumpConfig := &ethstate.DumpConfig{
		SkipCode:    false,
		SkipStorage: false,

		OnlyWithAddresses: false,
		Start:             nil,
		Max:               1000,
	}
	stateDump := eth_state.RawDump(dumpConfig)

	// Convert state dump to JSON format
	stateJSON := convertStateToJSON(&stateDump, testChain.Head().Header)

	// Call C function to process the JSON state
	cJSON := C.CString(stateJSON)
	defer C.free(unsafe.Pointer(cJSON))

	result := C.process_json_state_gpu(cJSON, C.uint(len(f.workers)))

	// Check the result
	if result != 0 {
		return fmt.Errorf("C++ GPU state processing returned error code: %d", result)
	}

	return nil
}

// convertStateToJSON converts a state dump to JSON string compatible with CuEVM's expected format
func convertStateToJSON(stateDump *ethstate.Dump, blockHeader *types.Header) string {
	// Create a map for the "pre" state format
	preState := make(map[string]map[string]interface{})

	for addrStr, account := range stateDump.Accounts {
		// Create account object
		accountMap := make(map[string]interface{})

		// Convert balance to hex format
		balanceBig := new(big.Int)
		balanceBig.SetString(account.Balance, 10)
		accountMap["balance"] = "0x" + balanceBig.Text(16)

		// Add nonce
		accountMap["nonce"] = fmt.Sprintf("0x%x", account.Nonce)

		// Add code if it exists
		if len(account.Code) > 0 {
			accountMap["code"] = "0x" + hex.EncodeToString(account.Code)
		} else {
			accountMap["code"] = "0x"
		}

		// Add storage if it exists
		if len(account.Storage) > 0 {
			storage := make(map[string]string)
			for key, value := range account.Storage {
				// Remove "0x" prefix if present in value
				if strings.HasPrefix(value, "0x") {
					value = value[2:]
				}

				// Store as "0x..." format
				storage["0x"+hex.EncodeToString(key.Bytes())] = "0x" + value
			}
			accountMap["storage"] = storage
		} else {
			accountMap["storage"] = make(map[string]string)
		}

		// Add to pre state
		preState[addrStr] = accountMap
	}

	// Create the final structure including env information
	stateStruct := map[string]interface{}{
		"pre": preState,
	}

	// Add block header information if available
	if blockHeader != nil {
		// Create env section with block header data
		envMap := make(map[string]interface{})

		// Format all values as hex strings
		envMap["currentCoinbase"] = "0x" + blockHeader.Coinbase.Hex()[2:]
		envMap["currentTimestamp"] = fmt.Sprintf("0x%x", blockHeader.Time)
		envMap["currentNumber"] = "0x" + blockHeader.Number.Text(16)
		envMap["currentDifficulty"] = "0x" + blockHeader.Difficulty.Text(16)
		envMap["currentGasLimit"] = fmt.Sprintf("0x%x", blockHeader.GasLimit)

		// Add default values for fields not in the go-ethereum header
		envMap["currentBaseFee"] = "0x0a" // Default base fee

		// Add prevrandao if available (for post-merge chains)
		// In go-ethereum this is stored in the mixHash field after the merge
		envMap["currentRandom"] = "0x" + hex.EncodeToString(blockHeader.MixDigest.Bytes())

		// Add default chain ID (typically 1 for mainnet)
		envMap["chainId"] = "0x1"

		// Add environment to state structure
		stateStruct["env"] = envMap
	}

	// Marshal to JSON
	jsonBytes, err := json.MarshalIndent(stateStruct, "", "  ")
	if err != nil {
		return "{}"
	}

	return string(jsonBytes)
}

// launchGPUKernel modification to handle chain state properly
func (f *Fuzzer) launchGPUKernel() error {
	f.logger.Info("Launching GPU kernel to execute call sequences with prepared element lists")

	// Process state data from our base test chain for GPU processing
	if len(f.workers) > 0 && f.workers[0] != nil && f.workers[0].chain != nil {
		err := f.prepareAndProcessChainStateInGPU(f.workers[0].chain)
		if err != nil {
			f.logger.Warn("Failed to prepare state data for GPU", err)
		}
	}

	// Initialize a slice to hold the growing call sequences for each worker
	allCallSequences := make([]calls.CallSequence, len(f.workers))
	for i := range allCallSequences {
		allCallSequences[i] = make(calls.CallSequence, 0)
	}

	// Process one element at a time from each worker
	for elementIdx := 0; elementIdx < len(f.workers[0].callSequenceElements); elementIdx++ {
		// Collect one element from each worker that has an element at this index
		elementsToProcess := make([]*calls.CallSequenceElement, 0)

		for workerIdx := 0; workerIdx < len(f.workers); workerIdx++ {
			worker := f.workers[workerIdx]
			if worker != nil && elementIdx < len(worker.callSequenceElements) {
				elementsToProcess = append(elementsToProcess, worker.callSequenceElements[elementIdx])
			}
		}

		// If we collected any elements, process them
		if len(elementsToProcess) > 0 {

			gpuResults, err := f.runTransactionsGPU(elementsToProcess)
			if err != nil {
				f.logger.Warn("Failed to get GPU execution results", err)
			} else if gpuResults != nil {
				// Build the call sequences incrementally and collect weights

				var workerWeights []*big.Int

				for i, worker := range f.workers {
					if worker != nil && elementIdx < len(worker.callSequenceElements) {
						// Add the current element to this worker's growing sequence
						allCallSequences[i] = append(allCallSequences[i], elementsToProcess[i])

						workerWeights = append(workerWeights, worker.getNewCorpusCallSequenceWeight())
					}
				}

				// fmt.Println("Medusa: workerWeights: ", workerWeights, "length: ", len(workerWeights))

				err = f.corpus.CheckGPUCoverageAndUpdate(
					gpuResults,
					f.contractAddressToCodeHash,
					allCallSequences,
					workerWeights,
					true)

				if err != nil || f.assertion_test_provider == nil {
					fmt.Println("CuEVM Debug: assertion_test_provider is nil or error in CheckGPUCoverageAndUpdate")
					return err
				}

				to_break, err := f.assertion_test_provider.GPUPostCallTest(f.workers, allCallSequences, gpuResults)
				if err != nil {
					return err
				}
				// fmt.Println("CuEVM Debug: to_break", to_break)
				// If our fuzzer context or the emergency context is cancelled, exit out immediately without results.
				if utils.CheckContextDone(f.ctx) || to_break {
					fmt.Println("\n\nCuEVM Debug: context done or to_break\n\n")
					return nil
				}
			}

		}

	}

	// Now process transaction data for each worker
	// for i := 0; i < len(f.workers); i++ {
	// 	worker := f.workers[i]
	// 	if worker == nil || worker.chain == nil {
	// 		continue
	// 	}

	// 	// Check if we should stop execution
	// 	if utils.CheckContextDone(f.emergencyCtx) || utils.CheckContextDone(f.ctx) {
	// 		break
	// 	}

	// 	// Execute the call sequence using the prepared list of elements (keeping existing code)
	// 	_, worker.lastExecutionError = calls.SimulateExecuteCallSequenceGPUWithList(
	// 		worker.chain,
	// 		worker.callSequenceElements,
	// 		worker.executionCheckFunc,
	// 	)
	// }

	return nil
}

// processWorkersResultsInParallel handles all post-processing logic in parallel
// Returns a boolean indicating if workers should be cancelled and an error if one occurred
func (f *Fuzzer) processWorkersResultsInParallel() (bool, error) {
	var wg sync.WaitGroup
	errChan := make(chan error, f.config.Fuzzing.Workers)
	cancelChan := make(chan bool, f.config.Fuzzing.Workers)

	for i := 0; i < len(f.workers); i++ {
		wg.Add(1)
		go func(workerIndex int) {
			defer wg.Done()

			worker := f.workers[workerIndex]
			if worker == nil || worker.chain == nil {
				return
			}

			// Check for emergency context cancellation
			if utils.CheckContextDone(f.emergencyCtx) {
				cancelChan <- true
				return
			}

			// Process execution results

			// If our fuzzer context is done, clear errors
			if utils.CheckContextDone(f.ctx) {
				worker.lastExecutionError = nil
			}

			// If this was not a new call sequence, indicate not to save the shrunken result to the corpus again
			if !worker.isNewSequence {
				for i := 0; i < len(worker.pendingShrinkRequests); i++ {
					worker.pendingShrinkRequests[i].RecordResultInCorpus = false
				}
			}

			// Add any new shrink requests to the worker's list for next iteration
			if len(worker.pendingShrinkRequests) > 0 {
				worker.shrinkCallSequenceRequests = append(worker.shrinkCallSequenceRequests, worker.pendingShrinkRequests...)
			}

			// Reset value set to original
			worker.valueSet = worker.originalValueSet

			// Reset chain state
			if worker.lastExecutionError == nil {
				err := worker.chain.RevertToBlockIndex(worker.testingBaseBlockIndex)
				if err != nil {
					errChan <- err
					return
				}
			} else {
				// Return any execution error
				errChan <- worker.lastExecutionError
				return
			}

			// Emit event indicating the worker finished testing a call sequence
			err := worker.Events.CallSequenceTested.Publish(FuzzerWorkerCallSequenceTestedEvent{
				Worker: worker,
			})
			if err != nil {
				errChan <- fmt.Errorf("error returned by an event handler: %v", err)
				return
			}

			// Update metrics
			worker.workerMetrics().sequencesTested.Add(worker.workerMetrics().sequencesTested, big.NewInt(1))
			worker.workerMetrics().callsTested.Add(worker.workerMetrics().callsTested, big.NewInt(int64(len(worker.callSequenceElements))))
			// fmt.Println("CuEVM Debug: worker.workerMetrics().sequencesTested", worker.workerMetrics().sequencesTested)
			// fmt.Println("CuEVM Debug: worker.workerMetrics().callsTested", worker.workerMetrics().callsTested)
			// Check if we've reached the worker reset limit
			sequencesTested := worker.workerMetrics().sequencesTested.Uint64()
			if sequencesTested > uint64(worker.fuzzer.config.Fuzzing.WorkerResetLimit) {
				// Close the chain to free resources
				if worker.chain != nil {
					worker.chain.Close()
					worker.chain = nil
				}
				worker.workerMetrics().sequencesTested = big.NewInt(0)
			}
		}(i)
	}

	// Wait for all workers to finish post-processing
	wg.Wait()
	close(errChan)
	close(cancelChan)

	// Check if there were any errors
	for err := range errChan {
		return false, err
	}

	// Check if any workers signaled cancellation
	for cancel := range cancelChan {
		if cancel {
			return true, nil
		}
	}

	return false, nil
}

// Start begins a fuzzing operation on the provided project configuration. This operation will not return until an error
// is encountered or the fuzzing operation has completed. Its execution can be cancelled using the Stop method.
// Returns an error if one is encountered.
func (f *Fuzzer) Start() error {
	// Define our variable to catch errors
	var err error

	// While we're fuzzing, we'll want to have an initialized random provider.
	// f.randomProvider = rand.New(rand.NewSource(time.Now().UnixNano()))
	// CuEVM Debug: fixed random provider
	f.randomProvider = rand.New(rand.NewSource(1))

	// Create our main and emergency running context (allows us to cancel across threads)
	f.ctx, f.ctxCancelFunc = context.WithCancel(context.Background())
	f.emergencyCtx, f.emergencyCtxCancelFunc = context.WithCancel(context.Background())

	// If we set a timeout, create the timeout context now, as we're about to begin fuzzing.
	if f.config.Fuzzing.Timeout > 0 {
		f.logger.Info("Running with a timeout of ", colors.Bold, f.config.Fuzzing.Timeout, " seconds")
		f.ctx, f.ctxCancelFunc = context.WithTimeout(f.ctx, time.Duration(f.config.Fuzzing.Timeout)*time.Second)
	}

	// Set up the corpus
	f.logger.Info("Initializing corpus")
	f.corpus, err = corpus.NewCorpus(f.config.Fuzzing.CorpusDirectory)
	if err != nil {
		f.logger.Error("Failed to create the corpus", err)
		return err
	}
	// Start the revert reporter
	f.revertReporter.Start(f.ctx)

	// Initialize our metrics and valueGenerator.
	f.metrics = newFuzzerMetrics(f.config.Fuzzing.Workers, f.revertReporter.RevertMetricsCh)

	// Initialize our test cases and providers
	f.testCasesLock.Lock()
	f.testCases = make([]TestCase, 0)
	f.testCasesFinished = make(map[string]TestCase)
	f.testCasesLock.Unlock()

	// Create our test chain
	baseTestChain, err := f.createTestChain()
	if err != nil {
		f.logger.Error("Failed to create the test chain", err)
		return err
	}

	// Set it up with our deployment/setup strategy defined by the fuzzer.
	f.logger.Info("Setting up test chain")
	trace, err := f.Hooks.ChainSetupFunc(f, baseTestChain)
	if err != nil {
		if trace != nil {
			f.logger.Error("Failed to initialize the test chain", err, errors.New(trace.Log().ColorString()))
		} else {
			f.logger.Error("Failed to initialize the test chain", err)
		}
		return err
	}
	f.logger.Info("Finished setting up test chain")

	// Initialize our coverage maps by measuring the coverage we get from the corpus.
	var corpusActiveSequences, corpusTotalSequences int
	if totalCallSequences, testResults := f.corpus.CallSequenceEntryCount(); totalCallSequences > 0 || testResults > 0 {
		f.logger.Info("Running call sequences in the corpus")
	}
	startTime := time.Now()
	corpusActiveSequences, corpusTotalSequences, err = f.corpus.Initialize(baseTestChain, f.contractDefinitions)
	if corpusTotalSequences > 0 {
		f.logger.Info("Finished running call sequences in the corpus in ", time.Since(startTime).Round(time.Second))
	}
	if err != nil {
		f.logger.Error("Failed to initialize the corpus", err)
		return err
	}

	// Log corpus health statistics, if we have any existing sequences.
	if corpusTotalSequences > 0 {
		f.logger.Info(
			colors.Bold, "corpus: ", colors.Reset,
			"health: ", colors.Bold, int(float32(corpusActiveSequences)/float32(corpusTotalSequences)*100.0), "%", colors.Reset, ", ",
			"sequences: ", colors.Bold, corpusTotalSequences, " (", corpusActiveSequences, " valid, ", corpusTotalSequences-corpusActiveSequences, " invalid)", colors.Reset,
		)
	}

	// Log the start of our fuzzing campaign.
	f.logger.Info("Fuzzing with ", colors.Bold, f.config.Fuzzing.Workers, colors.Reset, " workers")

	// Start our printing loop now that we're about to begin fuzzing.
	go f.printMetricsLoop()

	// Publish a fuzzer starting event.
	err = f.Events.FuzzerStarting.Publish(FuzzerStartingEvent{Fuzzer: f})
	if err != nil {
		f.logger.Error("FuzzerStarting event subscriber returned an error", err)
		return err
	}

	// If StopOnNoTests is true and there are no test cases, then throw an error
	if f.config.Fuzzing.Testing.StopOnNoTests && len(f.testCases) == 0 {
		err = fmt.Errorf("no assertion, property, optimization, or custom tests were found to fuzz")
		if !f.config.Fuzzing.Testing.TestViewMethods {
			err = fmt.Errorf("no assertion, property, optimization, or custom tests were found to fuzz and testing view methods is disabled")
		}
		f.logger.Error("Failed to start fuzzer", err)
		return err
	}
	fmt.Println("fuzzer start")
	fmt.Println("baseTestChain.CommittedBlocks(): ", baseTestChain.CommittedBlocks())
	fmt.Println("baseTestChain.State(): ", baseTestChain.State())
	// Run the main worker loop
	err = f.spawnWorkersLoop(baseTestChain)
	if err != nil {
		f.logger.Error("Encountered an error in the main fuzzing loop", err)
	}

	// NOTE: After this point, we capture errors but do not return immediately, as we want to exit gracefully.

	// If we have coverage enabled and a corpus directory set, write the corpus. We do this even if we had a
	// previous error, as we don't want to lose corpus entries.
	if f.config.Fuzzing.CoverageEnabled {
		corpusFlushErr := f.corpus.Flush()
		if err == nil && corpusFlushErr != nil {
			err = corpusFlushErr
			f.logger.Info("Failed to flush the corpus", err)
		}
	}

	// Publish a fuzzer stopping event.
	fuzzerStoppingErr := f.Events.FuzzerStopping.Publish(FuzzerStoppingEvent{Fuzzer: f, err: err})
	if err == nil && fuzzerStoppingErr != nil {
		err = fuzzerStoppingErr
		f.logger.Error("FuzzerStopping event subscriber returned an error", err)
	}

	// Print our results on exit.
	f.printExitingResults()

	// Finally, generate our coverage report if we have set a valid corpus directory.
	if err == nil && len(f.config.Fuzzing.CoverageFormats) > 0 {
		// Write to the default directory if we have no corpus directory set.
		coverageReportDir := filepath.Join("crytic-export", "coverage")
		if f.config.Fuzzing.CorpusDirectory != "" {
			coverageReportDir = filepath.Join(f.config.Fuzzing.CorpusDirectory, "coverage")
		}
		sourceAnalysis, err := coverage.AnalyzeSourceCoverage(f.compilations, f.corpus.CoverageMaps(), f.logger)

		if err != nil {
			f.logger.Error("Failed to analyze source coverage", err)
		} else {
			var path string
			for _, reportType := range f.config.Fuzzing.CoverageFormats {
				switch reportType {
				case "html":
					path, err = coverage.WriteHTMLReport(sourceAnalysis, coverageReportDir)
				case "lcov":
					path, err = coverage.WriteLCOVReport(sourceAnalysis, coverageReportDir)
				default:
					err = fmt.Errorf("unsupported coverage report type: %s", reportType)
				}
				if err != nil {
					f.logger.Error(fmt.Sprintf("Failed to generate %s coverage report", reportType), err)
				} else {
					f.logger.Info(fmt.Sprintf("%s report(s) saved to: %s", reportType, path), colors.Bold, colors.Reset)
				}
			}
		}
	}

	// Generate the revert metrics artifacts
	err = f.revertReporter.BuildArtifacts()
	if err != nil {
		f.logger.Error("Failed to write reversion metrics to disk", err)
	}

	// Return any encountered error.
	return err
}

// Stop attempts to stop all running operations invoked by the Start method. Note that Stop is not guaranteed to fully
// terminate the operations across all threads. For example, the optimization testing provider may request a thread to
// shrink some call sequences before the thread is torn down. Stop will not prevent those shrink requests from
// executing. An OS-level interrupt must be used to guarantee the stopping of _all_ operations (see Terminate).
func (f *Fuzzer) Stop() {
	// Call the cancel function on our main running context to try stop all working goroutines
	if f.ctxCancelFunc != nil {
		f.ctxCancelFunc()
	}
}

// Terminate is called to react to an OS-level interrupt (e.g. SIGINT) or an error. This will stop all operations.
// Note that this function will return before all operations are complete.
func (f *Fuzzer) Terminate() {
	// Call the emergency context cancel function on our running context to stop all working goroutines
	if f.emergencyCtxCancelFunc != nil {
		f.emergencyCtxCancelFunc()
	}

	// Cancel the main context as well
	if f.ctxCancelFunc != nil {
		f.ctxCancelFunc()
	}
}

// printMetricsLoop prints metrics to the console in a loop until ctx signals a stopped operation.
func (f *Fuzzer) printMetricsLoop() {
	// Define our start time
	startTime := time.Now()

	// Define cached variables for our metrics to calculate deltas.
	lastCallsTested := big.NewInt(0)
	lastSequencesTested := big.NewInt(0)
	lastWorkerStartupCount := big.NewInt(0)
	lastGasUsed := big.NewInt(0)

	lastPrintedTime := time.Time{}
	for !utils.CheckContextDone(f.ctx) {
		// Obtain our metrics
		callsTested := f.metrics.CallsTested()
		sequencesTested := f.metrics.SequencesTested()
		gasUsed := f.metrics.GasUsed()
		failedSequences := f.metrics.FailedSequences()
		workerStartupCount := f.metrics.WorkerStartupCount()
		workersShrinking := f.metrics.WorkersShrinkingCount()

		// Calculate time elapsed since the last update
		secondsSinceLastUpdate := time.Since(lastPrintedTime).Seconds()

		// Obtain memory usage stats
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		memoryUsedMB := memStats.Alloc / 1024 / 1024
		memoryTotalMB := memStats.Sys / 1024 / 1024

		// Print a metrics update
		logBuffer := logging.NewLogBuffer()
		logBuffer.Append(colors.Bold, "fuzz: ", colors.Reset)
		logBuffer.Append("elapsed: ", colors.Bold, time.Since(startTime).Round(time.Second).String(), colors.Reset)
		logBuffer.Append(", calls: ", colors.Bold, fmt.Sprintf("%d (%d/sec)", callsTested, uint64(float64(new(big.Int).Sub(callsTested, lastCallsTested).Uint64())/secondsSinceLastUpdate)), colors.Reset)
		logBuffer.Append(", seq/s: ", colors.Bold, fmt.Sprintf("%d", uint64(float64(new(big.Int).Sub(sequencesTested, lastSequencesTested).Uint64())/secondsSinceLastUpdate)), colors.Reset)
		logBuffer.Append(", branches hit: ", colors.Bold, fmt.Sprintf("%d", f.corpus.CoverageMaps().BranchesHit()), colors.Reset)
		logBuffer.Append(", corpus: ", colors.Bold, fmt.Sprintf("%d", f.corpus.ActiveMutableSequenceCount()), colors.Reset)
		logBuffer.Append(", failures: ", colors.Bold, fmt.Sprintf("%d/%d", failedSequences, sequencesTested), colors.Reset)
		logBuffer.Append(", gas/s: ", colors.Bold, fmt.Sprintf("%d", uint64(float64(new(big.Int).Sub(gasUsed, lastGasUsed).Uint64())/secondsSinceLastUpdate)), colors.Reset)
		if f.logger.Level() <= zerolog.DebugLevel {
			logBuffer.Append(", shrinking: ", colors.Bold, fmt.Sprintf("%v", workersShrinking), colors.Reset)
			logBuffer.Append(", mem: ", colors.Bold, fmt.Sprintf("%v/%v MB", memoryUsedMB, memoryTotalMB), colors.Reset)
			logBuffer.Append(", resets/s: ", colors.Bold, fmt.Sprintf("%d", uint64(float64(new(big.Int).Sub(workerStartupCount, lastWorkerStartupCount).Uint64())/secondsSinceLastUpdate)), colors.Reset)

			if time.Since(f.lastPCsLogMsg) >= timeBetweenPCsLogMsgs {
				start := time.Now()
				totalPCs, err := coverage.GetUniquePCsCount(f.compilations, f.corpus.CoverageMaps(), f.logger)
				// This is just for a log message. This shouldn't error but if it does we don't need to exit out
				if err == nil {
					end := time.Now()
					f.lastPCsLogMsg = end
					logBuffer.Append(", total PCs hit: ", colors.Bold, fmt.Sprintf("%v", totalPCs), colors.Reset)
					logBuffer.Append(", time to calculate total PCs hit: ", colors.Bold, fmt.Sprintf("%v", end.Sub(start)), colors.Reset)
				}
			}
		}
		f.logger.Info(logBuffer.Elements()...)

		// Update our delta tracking metrics
		lastPrintedTime = time.Now()
		lastCallsTested = callsTested
		lastSequencesTested = sequencesTested
		lastGasUsed = gasUsed
		lastWorkerStartupCount = workerStartupCount

		// If we reached our transaction threshold, halt
		// TODO: We should move this logic somewhere else because it is weird that the metrics loop halts the fuzzer
		testLimit := f.config.Fuzzing.TestLimit
		if testLimit > 0 && (!callsTested.IsUint64() || callsTested.Uint64() >= testLimit) {
			f.logger.Info("Transaction test limit reached, halting now...")
			f.Stop()
			break
		}

		// Sleep some time between print iterations
		time.Sleep(time.Second * 3)
	}
}

// printExitingResults prints the TestCase results prior to the fuzzer exiting.
func (f *Fuzzer) printExitingResults() {
	// Define the order our test cases should be sorted by when considering status.
	testCaseDisplayOrder := map[TestCaseStatus]int{
		TestCaseStatusNotStarted: 0,
		TestCaseStatusPassed:     1,
		TestCaseStatusFailed:     2,
		TestCaseStatusRunning:    3,
	}

	// Sort the test cases by status and then ID.
	sort.Slice(f.testCases, func(i int, j int) bool {
		// Sort by order first
		iStatusOrder := testCaseDisplayOrder[f.testCases[i].Status()]
		jStatusOrder := testCaseDisplayOrder[f.testCases[j].Status()]
		if iStatusOrder != jStatusOrder {
			return iStatusOrder < jStatusOrder
		}

		// Then we sort by ID.
		return strings.Compare(f.testCases[i].ID(), f.testCases[j].ID()) <= 0
	})

	// Define variables to track our final test count.
	var (
		testCountPassed int
		testCountFailed int
	)

	// Print the results of each individual test case.
	f.logger.Info("Fuzzer stopped, test results follow below ...")
	for _, testCase := range f.testCases {
		f.logger.Info(testCase.LogMessage().ColorString())

		// Tally our pass/fail count.
		if testCase.Status() == TestCaseStatusPassed {
			testCountPassed++
		} else if testCase.Status() == TestCaseStatusFailed {
			testCountFailed++
		}
	}

	// Print our final tally of test statuses.
	f.logger.Info("Test summary: ", colors.GreenBold, testCountPassed, colors.Reset, " test(s) passed, ", colors.RedBold, testCountFailed, colors.Reset, " test(s) failed")
}
