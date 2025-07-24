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
    uint32_t bug_thread_idx;  // Thread index
    uint32_t bug_id;          // id of the bug (pc << 16 | bug_type) // to be decoded
} BugInfoEntry;

typedef struct {
    uint32_t branch_thread_idx;  // Thread index
    uint32_t branch_id;          // Branch ID (pc_src << 16 | pc_dst) // to be decoded
} BranchInfoEntry;

typedef struct {
    uint32_t storage_thread_idx;  // Thread index
    uint32_t
        storage_id;  // Storage ID (account_idx (8bit) | storate_type (8bit) | storage_slot (16bit)) // to be decoded
    // storage_type: 1 for write, 2 for read, 3 for balance
} StorageInfoEntry;

typedef struct {
    uint32_t new_branch_count;
    uint32_t new_bug_count;
    uint32_t new_storage_count;
} GPUFeedbackCount;

typedef struct {
    BranchInfoEntry* new_branch_info;
    uint32_t num_new_branch;
    BugInfoEntry* new_bug_info;
    uint32_t num_new_bug;
    StorageInfoEntry* new_storage_info;
    uint32_t num_new_storage;
} SimplifiedGPUResultSingleBatchC;

typedef struct {
    SimplifiedGPUResultSingleBatchC* results;
    uint32_t num_results;
} SimplifiedGPUResultC;

// Updated function declaration with reuse_state_data parameter
SimplifiedGPUResultC* process_batch_transactions(const uint64_t* blockNumber, const uint64_t* timeStamp,
                                                 const unsigned char* fromAddr, const unsigned char* toAddr,
                                                 const unsigned char* values,
                                                 const unsigned char* callData,
                                                 uint32_t callDataLen, const uint32_t* dataOffsets,
                                                 const uint32_t* dataSizes, const int32_t* markerOffsets,
												 const uint32_t* markerData,
												 uint32_t markerDataLen, uint32_t txBatchCount, uint32_t sequenceLength, uint32_t start_seed);

// Updated function declaration with reset_state parameter
// int process_json_state_gpu(const char* json_state, uint32_t num_instances, bool reset_state);
int process_json_state_gpu(const char* json_state, uint32_t num_instances, bool reset_state, uint32_t skipTxSize, const char* constants,
							const uint32_t* markerData, uint32_t markerDataLen);

uint32_t get_num_instances_per_device();

// Function to free SimplifiedGPUResultC
void free_simplified_gpu_result(SimplifiedGPUResultC* result);
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
	// CuEVM: CPU workers is fixed to number of threads
	numCPUWorkers         int
	sequencesPerCPUWorker int
	GPUchainInitiated     bool
	numInstancesPerDevice int
	loopCounter           int
	currentRandomSeed     uint32 // current seed for the LCG generator in GPU. Default = loopCounter. Change every batch of tx.
	forkMode              bool   // if true, use fork mode to initialize the test chain
	// CuEVM debug: skip sequence size
	skipSequenceSize          int
	originalNonceMap          map[common.Address]uint64
	signatureDynamicEncoding  []string             // all the methods with dynamic encoding
	staticABIMarkers          [][]calls.DataMarker // markers of all the methods w/o dynamic encoding
	staticABISignature        []string             // not safe to modified by multiple threads
	staticABIMarkerIndexMap   map[string]int       // mapping of signature to offset in the flattened markers
	staticABICallData         [][]byte             // not safe to modified by multiple threads
	staticABIDataABIValues    []calls.CallMessageDataAbiValues
	staticABIFlattenedMarkers []uint32 // flattened markers of all the methods w/o dynamic encoding
	staticABIMarkerOffset     []uint32 // mapping of signature to offset in the flattened markers

	pendingEvents   []chain.ContractDeploymentsAddedEvent
	addressIndexMap map[common.Address]uint8 // mapping from address to index in the address addressConstants array

	functionImpactsCache      map[string][]string // signature -> impacts
	functionIsImpactedCache   map[string][]string // signature -> isImpactedBy
	functionsWithImpactsCache []string            // signatures that have impacts (for first element)
	normalizedSigCache        map[string]string   // signature -> normalized signature

	// convenient fuzzing metrics storage
	callsTested   int
	fuzzStartTime time.Time
	PCsLogs       []int
	// CuEVM debug: shrink workers
	shrinkWorker *FuzzerWorker

	addressConstants []string // hex string
	integerConstants []string // hex string

	// Pre-allocated arrays for GPU processing to avoid repeated allocations
	gpuDataOffsets   []uint32
	gpuDataSizes     []uint32
	gpuMarkerOffsets []int32
	gpuFromAddr      []uint8

	gpuBlockNumbers []uint64
	gpuTimeStamps   []uint64

	// Pre-allocated buffer for call data to reduce GC pressure
	gpuCallDataBuffer []byte

	// CuEVM debug: for directly calling in fuzzing loop
	property_test_provider     *PropertyTestCaseProvider
	assertion_test_provider    *AssertionTestCaseProvider
	optimization_test_provider *OptimizationTestCaseProvider
}

// Amount of time between "total PCs hit" log messages. This message is only output when debug logging is enabled.
const timeBetweenPCsLogMsgs = 2 * time.Second //time.Minute

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
		addressIndexMap:           make(map[common.Address]uint8),
		revertReporter:            revertReporter,
		Hooks: FuzzerHooks{
			NewCallSequenceGeneratorConfigFunc: defaultCallSequenceGeneratorConfigFunc,
			NewShrinkingValueMutatorFunc:       defaultShrinkingValueMutatorFunc,
			ChainSetupFunc:                     chainSetupFromCompilations,
			CallSequenceTestFuncs:              make([]CallSequenceTestFunc, 0),
		},
		logger:           logger,
		skipSequenceSize: 32,
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
	// CuEVM Debug: constant skip sequence size

	fuzzer.staticABIMarkerIndexMap = make(map[string]int)
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
	fmt.Println("CuEVM Debug: seedFromAST", seedFromAST)
	fmt.Println("CuEVM Debug: slitherResults", slitherResults)

	// If we have results and there were no errors, we will seed the value set using the slither results
	if !seedFromAST {
		f.slitherResults = slitherResults
		// Seed our base value set with the constants extracted by Slither
		f.baseValueSet.SeedFromSlither(slitherResults)
		sender_set := make(map[common.Address]bool)
		// CuEVM add address constants to sender list
		constant_count := 0
		for _, constant := range slitherResults.Constants {
			if constant.Type == "address" {
				var addressBigInt, _ = new(big.Int).SetString(constant.Value, 10)
				address := common.BigToAddress(addressBigInt)
				if err != nil {
					f.logger.Warn("Failed to convert constant to address", err)
				}
				if !sender_set[address] {
					f.senders = append(f.senders, address)
					constant_count++
					if constant_count > 16 {
						// dont extract so many to become sender
						break
					}
					sender_set[address] = true
				}
			}
		}
	}
	// sort senders for deterministic mutation
	sort.Slice(f.senders, func(i, j int) bool {
		return f.senders[i].Hex() < f.senders[j].Hex()
	})

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
func (f *Fuzzer) createTestChain(additionalGenesisAlloc *types.GenesisAlloc) (*chain.TestChain, error) {
	// Create our genesis allocations.
	// NOTE: Sharing GenesisAlloc between chains will result in some accounts not being funded for some reason.
	genesisAlloc := make(types.GenesisAlloc)
	if additionalGenesisAlloc != nil {
		fmt.Println("CuEVM Debug: additionalGenesisAlloc")
		for addr, account := range *additionalGenesisAlloc {
			genesisAlloc[addr] = account
		}
	}
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
						// return nil, fmt.Errorf("constructor arguments for contract %s not provided", contractName)
						fmt.Printf("constructor arguments for contract %s not provided, trying to randomize\n", contractName)
						// CuEVM Debug: use random values for constructor arguments

						// Create a temporary random value generator for constructor arguments using default config
						tempGenerator := valuegeneration.NewRandomValueGenerator(getDefaultRandomValueGeneratorConfig(), fuzzer.randomProvider)

						// Generate values for all constructor inputs
						generatedValues := make([]any, len(contract.CompiledContract().Abi.Constructor.Inputs))
						for i, input := range contract.CompiledContract().Abi.Constructor.Inputs {
							generatedValues[i] = valuegeneration.GenerateAbiValue(tempGenerator, &input.Type)

							if input.Type.T == abi.AddressTy {
								generatedValues[i] = fuzzer.deployer
								fmt.Println("CuEVM Debug: generatedValues", generatedValues[i], input.Type)
							}
						}

						// Encode all values to JSON format (this converts big.Int to string, etc.)
						var err error
						jsonArgs, err = valuegeneration.EncodeJSONArgumentsToMap(contract.CompiledContract().Abi.Constructor.Inputs, generatedValues)
						if err != nil {
							return nil, fmt.Errorf("failed to encode generated constructor arguments for contract %s: %v", contractName, err)
						}
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
				fmt.Println("CuEVM Debug: PendingBlockCreate", fuzzer.forkMode)
				// Create a new pending block we'll commit to chain
				block, err := testChain.PendingBlockCreate()
				if err != nil {
					return nil, err
				}

				// Add our transaction to the block
				err = testChain.PendingBlockAddTx(msg.ToCoreMessage())
				fmt.Println("CuEVM Debug: err PendingBlockAddTx", err)
				if err != nil {
					return nil, err
				}

				// Commit the pending block to the chain, so it becomes the new head.
				err = testChain.PendingBlockCommit()

				if err != nil {
					// if fuzzer.forkMode {
					// fail to run fork, we try to set the runtime bytecode
					// testChain.PendingBlockDiscard()
					fmt.Println("CuEVM Debug: fail, we try last resort to set the runtime bytecode")
					message_receipt := block.MessageResults[0].Receipt

					// if fork mode and fail, we try last resort to set the runtime bytecode
					found = true
					deployedContractAddr[contractName] = message_receipt.ContractAddress
					block.MessageResults[0].ContractDeploymentChanges[0].Contract.RuntimeBytecode = contract.CompiledContract().RuntimeBytecode
					for i := 0; i < len(block.MessageResults); i++ {
						for _, deploymentChange := range block.MessageResults[i].ContractDeploymentChanges {
							deploymentChange.Contract.RuntimeBytecode = contract.CompiledContract().RuntimeBytecode
							fuzzer.pendingEvents = append(fuzzer.pendingEvents, chain.ContractDeploymentsAddedEvent{
								Contract:          deploymentChange.Contract,
								DynamicDeployment: deploymentChange.DynamicCreation,
							})
						}
					}

					testChain.PendingBlockDiscard()
					// break

					// }
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

					// if fuzzer.forkMode
					{
						fmt.Println("CuEVM Debug: forkMode and fail, we try last resort to set the runtime bytecode")
						message_receipt := block.MessageResults[0].Receipt
						deployedContractAddr[contractName] = message_receipt.ContractAddress

						// if fork mode and fail, we try last resort to set the runtime bytecode
						for i := 0; i < len(block.MessageResults); i++ {
							for _, deploymentChange := range block.MessageResults[i].ContractDeploymentChanges {
								deploymentChange.Contract.RuntimeBytecode = contract.CompiledContract().RuntimeBytecode
								fuzzer.pendingEvents = append(fuzzer.pendingEvents, chain.ContractDeploymentsAddedEvent{
									Contract:          deploymentChange.Contract,
									DynamicDeployment: deploymentChange.DynamicCreation,
								})
							}
						}
						fmt.Println("CuEVM Debug: block.MessageResults[0].Receipt.ContractAddress", block.MessageResults[0].Receipt.ContractAddress)
						fmt.Println("CuEVM Debug: contractName", contractName)
						fmt.Println("pending events", len(fuzzer.pendingEvents))
						deployedContractAddr[contractName] = block.MessageResults[0].Receipt.ContractAddress
						found = true
						// break
					}

					// if err != nil {
					// 	return nil, fmt.Errorf("failed to reset to genesis block: %v", err)
					// } else {
					// 	_, err = calls.ExecuteCallSequenceWithExecutionTracer(testChain, fuzzer.contractDefinitions, []*calls.CallSequenceElement{cse}, config.VeryVeryVerbose)
					// 	if err != nil {
					// 		return nil, fmt.Errorf("deploying %s returned a failed status: %v", contractName, block.MessageResults[0].ExecutionResult.Err)
					// 	}
					// }

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

// getDefaultRandomValueGeneratorConfig returns the default RandomValueGeneratorConfig used throughout the fuzzer
func getDefaultRandomValueGeneratorConfig() *valuegeneration.RandomValueGeneratorConfig {
	return &valuegeneration.RandomValueGeneratorConfig{
		GenerateRandomArrayMinSize:  0,
		GenerateRandomArrayMaxSize:  8, // CuEVM debug
		GenerateRandomBytesMinSize:  0,
		GenerateRandomBytesMaxSize:  64,
		GenerateRandomStringMinSize: 0,
		GenerateRandomStringMaxSize: 64,
	}
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
		RandomValueGeneratorConfig:      getDefaultRandomValueGeneratorConfig(),
	}
	mutationalGenerator := valuegeneration.NewMutationalValueGenerator(mutationalGeneratorConfig, valueSet, randomProvider)

	// Create a sequence generator config which uses the created value generator.
	sequenceGenConfig := &CallSequenceGeneratorConfig{
		NewSequenceProbability:                   0.2,
		RandomUnmodifiedCorpusHeadWeight:         800,
		RandomUnmodifiedCorpusTailWeight:         800,
		RandomUnmodifiedSpliceAtRandomWeight:     200,
		RandomUnmodifiedInterleaveAtRandomWeight: 100,
		RandomMutatedCorpusHeadWeight:            80,
		RandomMutatedCorpusTailWeight:            40,
		RandomMutatedSpliceAtRandomWeight:        20,
		RandomMutatedInterleaveAtRandomWeight:    10,
		FunctionRelationBias:                     0.9, // CuEVM: mutate based on function relations 0.8
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
	f.workers = make([]*FuzzerWorker, f.numCPUWorkers)
	fmt.Println("CuEVM Debug: context done", utils.CheckContextDone(f.ctx))
	// Create all workers upfront
	for i := 0; i < f.numCPUWorkers; i++ {
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
				// errChan <- err
				return err
			}

			// Emit an event indicating the worker has set up its chain
			err = worker.Events.FuzzerWorkerChainSetup.Publish(FuzzerWorkerChainSetupEvent{
				Worker: worker,
				Chain:  worker.chain,
			})
			if err != nil {
				// errChan <- fmt.Errorf("error returned by an event handler: %v", err)
				return err
			}

			// Increase our generation metric
			worker.workerMetrics().workerStartupCount.Add(worker.workerMetrics().workerStartupCount, big.NewInt(1))

			// Save the current block index as all contracts have been deployed at this point
			worker.testingBaseBlockIndex = uint64(len(worker.chain.CommittedBlocks()))

		}
		if len(f.pendingEvents) > 0 {
			fmt.Println("CuEVM Debug: pendingEvents in worker chain creation", len(f.pendingEvents))
			for _, event := range f.pendingEvents {
				worker.chain.Events.ContractDeploymentAddedEventEmitter.Publish(event)
			}
		}

	}

	// CuEVM debug: one shrink worker only to record bug
	f.shrinkWorker, _ = newFuzzerWorker(f, 0, f.randomProvider)

	f.shrinkWorker.chain, _ = baseTestChain.Clone(func(initializedChain *chain.TestChain) error {
		// Subscribe our chain event handlers
		initializedChain.Events.ContractDeploymentAddedEventEmitter.Subscribe(f.shrinkWorker.onChainContractDeploymentAddedEvent)
		initializedChain.Events.ContractDeploymentRemovedEventEmitter.Subscribe(f.shrinkWorker.onChainContractDeploymentRemovedEvent)

		// If we have coverage-guided fuzzing enabled, create a tracer to collect coverage and connect it to the chain
		if f.config.Fuzzing.CoverageEnabled {
			f.shrinkWorker.coverageTracer = coverage.NewCoverageTracer()
			initializedChain.AddTracer(f.shrinkWorker.coverageTracer.NativeTracer(), true, false)
		}

		// Copy the labels from the base chain to the worker's chain
		initializedChain.Labels = maps.Clone(baseTestChain.Labels)

		// Emit an event indicating the worker has created its chain
		err := f.shrinkWorker.Events.FuzzerWorkerChainCreated.Publish(FuzzerWorkerChainCreatedEvent{
			Worker: f.shrinkWorker,
			Chain:  initializedChain,
		})
		// fmt.Println("error in fuzzer worker chain created clone", err)
		return err
	})
	f.shrinkWorker.testingBaseBlockIndex = uint64(len(f.shrinkWorker.chain.CommittedBlocks()))

	f.loopCounter = 0
	f.PrepareNonce(baseTestChain)
	// make sure chain is initialized before this step
	f.workers[0].sequenceGenerator.seedSequenceElementCache()
	// print out the cache
	// fmt.Println("CuEVM Debug: signatureDynamicEncoding", f.signatureDynamicEncoding)
	// for i := 0; i < len(f.staticABICallData); i++ {

	// 	fmt.Println("CuEVM Debug: staticABICallData", hex.EncodeToString(f.staticABICallData[i]))
	// 	fmt.Println("CuEVM Debug: staticABISignature", f.staticABISignature[i])
	// 	fmt.Println("CuEVM Debug: staticABIMarkers", f.staticABIMarkers[i])
	// 	fmt.Println("CuEVM Debug: staticABIMarkerIndexMap", f.staticABIMarkerIndexMap[f.staticABISignature[i]])
	// }

	// TODO: clone to other workers
	// Main processing loop
	working := true
	for working && !utils.CheckContextDone(f.ctx) {
		// Step 1: Prepare data in parallel
		workersCancelled, err := f.prepareWorkersDataInParallel()
		if err != nil {
			fmt.Println("CuEVM Debug: prepareWorkersDataInParallel error", err)
			return err
		}
		if workersCancelled {
			working = false
			continue
		}

		// Step 2: Launch GPU kernel - focusing only on testNextCallSequence
		err = f.launchGPUKernel()
		if err != nil {
			fmt.Println("CuEVM Debug: launchGPUKernel error", err)
			return err
		}

		// Step 3: Process results in parallel
		workersCancelled, err = f.processWorkersResultsInParallel()
		if err != nil {
			fmt.Println("CuEVM Debug: processWorkersResultsInParallel error", err)
			return err
		}
		if workersCancelled {
			working = false
		}

		f.loopCounter++

		// if f.loopCounter == 2 {
		// 	working = false
		// }
		// CuEVM Debug
		fmt.Printf("\n Medusa loop counter: %d\n", f.loopCounter)
		f.callsTested = f.loopCounter * f.sequencesPerCPUWorker * f.numCPUWorkers * f.config.Fuzzing.CallSequenceLength * f.skipSequenceSize

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
func (f *Fuzzer) PrepareNonce(baseTestChain *chain.TestChain) {
	f.originalNonceMap = make(map[common.Address]uint64)
	for _, address := range f.config.Fuzzing.SenderAddresses {
		f.originalNonceMap[common.HexToAddress(address)] = baseTestChain.State().GetNonce(common.HexToAddress(address))
	}
	fmt.Println("CuEVM Debug: originalNonceMap", f.originalNonceMap)
}

// prepareWorkersDataInParallel handles all setup logic from run() in parallel
// Returns a boolean indicating if workers should be cancelled and an error if one occurred
func (f *Fuzzer) prepareWorkersDataInParallel() (bool, error) {
	var wg sync.WaitGroup
	errChan := make(chan error, f.numCPUWorkers)
	cancelChan := make(chan bool, f.numCPUWorkers)

	// sequential update shrink requests :
	// for i := 0; i < f.numCPUWorkers; i++ {
	// 	// for _, shrinkCallSequenceRequest := range f.workers[i].shrinkCallSequenceRequests {

	// 	// 	// Enqueue for async processing (non-blocking)
	// 	// 	select {
	// 	// 	// only one shrink worker
	// 	// 	case f.shrinkWorker.shrinkRequestChan <- shrinkCallSequenceRequest:
	// 	// 		// enqueued successfully
	// 	// 	default:
	// 	// 		fmt.Println("shrinkRequestChan full, dropping shrink request")
	// 	// 	}
	// 	// }
	// 	// Clear shrink requests now that they've been processed

	// }
	for i := 0; i < f.numCPUWorkers; i++ {
		wg.Add(1)
		go func(workerIndex int) {
			defer wg.Done()

			worker := f.workers[workerIndex]
			if worker == nil {
				return
			}
			worker.shrinkCallSequenceRequests = nil

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

			if f.loopCounter == 0 {
				// construct staticABICallElementCache from fuzzer arrays
				worker.initializeABICache()
			}
			// fmt.Println("CuEVM Debug: workerIdx", workerIndex, "worker.shrinkCallSequenceRequests", len(worker.shrinkCallSequenceRequests))
			// Process any pending shrink requests
			// for _, shrinkCallSequenceRequest := range worker.shrinkCallSequenceRequests {
			// 	if utils.CheckContextDone(f.emergencyCtx) {
			// 		cancelChan <- true
			// 		return
			// 	}
			// 	if worker.chain == nil {
			// 		fmt.Println("worker.chain is nil, skipping shrink call sequence request")
			// 		break
			// 	}
			// 	_, err := worker.shrinkCallSequence(shrinkCallSequenceRequest)
			// 	if err != nil {
			// 		errChan <- err
			// 		return
			// 	}
			// }
			// CuEVM async equivalent
			// for _, shrinkCallSequenceRequest := range worker.shrinkCallSequenceRequests {
			// 	if utils.CheckContextDone(f.emergencyCtx) {
			// 		cancelChan <- true
			// 		return
			// 	}
			// 	// Enqueue for async processing (non-blocking)
			// 	select {
			// 	case f.shrinkWorkers[workerIndex].shrinkRequestChan <- shrinkCallSequenceRequest:
			// 		// enqueued successfully
			// 	default:
			// 		fmt.Println("shrinkRequestChan full, dropping shrink request")
			// 	}
			// }
			// // // Clear shrink requests now that they've been processed
			// worker.shrinkCallSequenceRequests = nil

			// If fuzzing is complete, signal cancellation
			if fuzzingComplete {
				cancelChan <- true
				return
			}

			{
				// If we already have a chain, revert to the base state
				err := worker.chain.RevertToBlockIndex(worker.testingBaseBlockIndex)
				if err != nil {
					errChan <- err
					return
				}
			}

			// Prepare execution data for GPU kernel
			worker.originalValueSet = worker.valueSet.Clone()

			// Prepare a fresh list for shrink requests
			worker.pendingShrinkRequests = make([]ShrinkCallSequenceRequest, 0)

			// Create execution check function for this worker
			worker.executionCheckFunc = func(currentlyExecutedSequence calls.CallSequence) (bool, error) {
				return false, nil
			}

			// NEW: Reuse the pre-allocated call sequence elements (already allocated in initializeABICache)
			// Clear the existing elements by setting them to nil
			// for seqIdx := 0; seqIdx < f.sequencesPerCPUWorker; seqIdx++ {
			// 	for elemIdx := 0; elemIdx < f.config.Fuzzing.CallSequenceLength; elemIdx++ {
			// 		worker.callSequenceElements[seqIdx][elemIdx] = nil
			// 	}
			// }

			// Generate multiple sequences per worker
			for seqIdx := 0; seqIdx < f.sequencesPerCPUWorker; seqIdx++ {
				// Initialize a new sequence within our sequence generator

				isNewSequence, err := worker.sequenceGenerator.InitializeNextSequence()
				if err != nil {
					fmt.Println("CuEVM Debug: InitializeNextSequence error, use blank sequence", err)
					err = nil
					// errChan <- err
					// return
				}
				// Store if this is a new sequence (only for the first one as that's what current code uses)
				if seqIdx == 0 {
					worker.isNewSequence = isNewSequence
				}

				// Initialize a new sequence array
				// worker.callSequenceElements[seqIdx] = make([]*calls.CallSequenceElement, 0)

				// Track nonces for each sender address within this sequence
				nonceMap := make(map[common.Address]uint64)
				for address, nonce := range f.originalNonceMap {
					nonceMap[address] = nonce
				}
				elementIdx := 0
				// Populate this sequence with elements from the sequence generator
				for {
					element, err := worker.sequenceGenerator.PopSequenceElement()
					if err != nil {
						fmt.Println("CuEVM Debug: PopSequenceElement error", err)
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

						if exists {
							// Update nonce if it's not greater than the current nonce for this sender
							element.Call.Nonce = currentNonce
						} else {
							element.Call.Nonce = 0
						}

						// Update the nonce map with the latest value
						nonceMap[sender] = element.Call.Nonce + 1
					}

					// worker.callSequenceElements[seqIdx] = append(worker.callSequenceElements[seqIdx], element)
					worker.callSequenceElements[seqIdx][elementIdx] = element
					elementIdx++
				}
			}

			// Emit event indicating the worker is about to test new call sequences
			// err := worker.Events.CallSequenceTesting.Publish(FuzzerWorkerCallSequenceTestingEvent{
			// 	Worker: worker,
			// })
			// if err != nil {
			// 	errChan <- fmt.Errorf("error returned by an event handler: %v", err)
			// 	return
			// }
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
func (f *Fuzzer) runTransactionsGPU(workers []*FuzzerWorker, txBatchSize, sequenceLength int) (*coverage.GPUExecutionResult, error) {
	fmt.Println("\nGo: Preparing transaction data in batch for GPU processing worker\n")
	// debug printing all sequences with idx
	// for workerIdx, worker := range f.workers {
	// 	for sequenceIdx, sequence := range worker.callSequenceElements {
	// 		fmt.Println("CuEVM Debug: worker", workerIdx, "sequence", sequenceIdx)
	// 		for elementIdx, element := range sequence {
	// 			fmt.Println("CuEVM Debug: element", elementIdx, element)
	// 		}
	// 	}
	// }

	// update the current random seed for the LCG generator in GPU.
	f.currentRandomSeed = uint32(f.randomProvider.Int31()) // always positive value

	var markerData []uint32

	// Use pre-allocated arrays instead of creating new ones
	toAddr := make([]byte, 32)

	// Copy to address (right-padded to 32 bytes) - keeping single to address for now
	copy(toAddr[12:], workers[0].callSequenceElements[0][0].Call.To.Bytes())

	// For data we need the data itself and offsets
	var callData []byte

	// one marker offset per thread group  (divisible by f.skipSequenceSize)
	// markerOffsets is now pre-allocated as f.gpuMarkerOffsets
	// merker data start with the count. followed by the 3 ints per marker
	// markerDataSize := 0

	// First pass: calculate total call data size needed
	totalCallDataSize := 0
	for elementIdx := 0; elementIdx < f.config.Fuzzing.CallSequenceLength; elementIdx++ {
		for workerIdx := 0; workerIdx < len(f.workers); workerIdx++ {
			worker := f.workers[workerIdx]
			for sequenceIdx := 0; sequenceIdx < len(worker.callSequenceElements); sequenceIdx++ {
				call := worker.callSequenceElements[sequenceIdx][elementIdx].Call
				if call != nil && len(call.Data) > 0 {
					totalCallDataSize += len(call.Data) * f.skipSequenceSize
				}
			}
		}
	}

	// Pre-allocate or reuse the call data buffer
	if cap(f.gpuCallDataBuffer) < totalCallDataSize {
		f.gpuCallDataBuffer = make([]byte, 0, totalCallDataSize)
	} else {
		f.gpuCallDataBuffer = f.gpuCallDataBuffer[:0] // Reset length, keep capacity
	}
	callData = f.gpuCallDataBuffer

	// Fill arrays from call elements
	idx := 0
	dataOffset := 0
	markerOffset := 0
	// zero := big.NewInt(0)
	for elementIdx := 0; elementIdx < f.config.Fuzzing.CallSequenceLength; elementIdx++ {
		for workerIdx := 0; workerIdx < len(f.workers); workerIdx++ {
			worker := f.workers[workerIdx]
			for sequenceIdx := 0; sequenceIdx < len(worker.callSequenceElements); sequenceIdx++ {
				// fmt.Println("CuEVM Debug:", workerIdx, sequenceIdx, elementIdx, worker.callSequenceElements[sequenceIdx][elementIdx])

				call := worker.callSequenceElements[sequenceIdx][elementIdx].Call
				element := worker.callSequenceElements[sequenceIdx][elementIdx]
				if call == nil {
					fmt.Println("\n\nCuEVM Debug: call is nil\n\n")
					idx++
					continue

				}
				// Warning, implement the logic of min delay = 1 in call_sequence_execution.go
				// line 280 - 286
				f.gpuBlockNumbers[idx] = max(1, element.BlockNumberDelay)
				f.gpuTimeStamps[idx] = max(1, element.BlockTimestampDelay)
				for i := 0; i < elementIdx; i++ {
					f.gpuBlockNumbers[idx] += max(1, element.BlockNumberDelay)
					f.gpuTimeStamps[idx] += max(1, element.BlockTimestampDelay)
				}

				// if call.Value.Cmp(zero) != 0 {
				// 	valueBytes := call.Value.Bytes()
				// 	copy(values[idx*32+32-len(valueBytes):idx*32+32], valueBytes)
				// }
				// fmt.Println("CuEVM Debug: worker", workerIdx, "sequence", sequenceIdx, "element", elementIdx, "call.Data", hex.EncodeToString(call.Data), "callDataLen", len(call.Data))
				// Optimized call data handling - append data once for all skip sequences
				callDataLen := len(call.Data)

				if callDataLen > 0 {
					// Grow slice once for all skip sequences
					currentLen := len(callData)
					totalDataToAdd := callDataLen * f.skipSequenceSize
					callData = callData[:currentLen+totalDataToAdd] // Grow slice once

					// Copy data efficiently for each skip sequence
					for k := 0; k < f.skipSequenceSize; k++ {
						copy(callData[currentLen+k*callDataLen:], call.Data)
					}
				}

				// Set offsets and sizes for all skip sequences
				for k := 0; k < f.skipSequenceSize; k++ {
					// f.gpuFromAddr[idx * f.skipSequenceSize + k] = 0
					f.gpuDataOffsets[idx*f.skipSequenceSize+k] = uint32(dataOffset)
					f.gpuDataSizes[idx*f.skipSequenceSize+k] = uint32(callDataLen)
					dataOffset += callDataLen

					f.gpuFromAddr[idx*f.skipSequenceSize+k] = f.addressIndexMap[element.Call.From]
					f.gpuBlockNumbers[idx*f.skipSequenceSize+k] = element.BlockNumberDelay
					f.gpuTimeStamps[idx*f.skipSequenceSize+k] = element.BlockTimestampDelay
				}
				cachedMarkerOffset, exists := worker.staticABIMarkerOffsetCache[call.DataAbiValues.Method.Sig]

				// fmt.Println("CuEVM Debug: cachedMarkerOffset", cachedMarkerOffset, "exists", exists)
				if exists {
					f.gpuMarkerOffsets[idx] = int32(-1 - cachedMarkerOffset) // start from -1 down, to not overlap with 0
				} else {
					f.gpuMarkerOffsets[idx] = int32(markerOffset)
					// fmt.Println("CuEVM Debug: idx", idx, "idx/f.skipSequenceSize", idx/f.skipSequenceSize, "markerOffset", markerOffset)
					// dynamic ABI encoding, need to add the markers to the markerData
					// fmt.Println("CuEVM Debug: idx", idx, "call.DataMarkers length", len(call.DataMarkers))
					// append the markers count first followed by the 3 ints per marker
					markerData = append(markerData, uint32(len(call.DataMarkers)))
					for _, marker := range call.DataMarkers {
						// fmt.Println("CuEVM Debug: marker", idx, marker.Offset, marker.Type, marker.Length)
						markerData = append(markerData, uint32(marker.Offset))
						markerData = append(markerData, uint32(marker.Type))
						markerData = append(markerData, uint32(marker.Length))
					}
					markerOffset += 1 + len(call.DataMarkers)*3 // 3 ints per marker + 1 int for the count

				}
				idx++
			}

			// if idx%txBatchSize == 0 {
			// 	// Reset data offset for each batch
			// 	dataOffset = 0
			// 	// CuEVM debug June 25, the reduced markerdata is shared across all batches
			// 	// markerOffset = 0
			// }
		}
		// reset the data offset for the batch
		dataOffset = 0

	}

	// fmt.Println("CuEVM Debug: markerDataSize", markerDataSize)
	// fmt.Println("CuEVM Debug: markerData", markerData)
	// fmt.Println("CuEVM Debug: markerOffsets", f.gpuMarkerOffsets)

	cMarkerOffsets := (*C.int)(nil)
	cMarkerData := (*C.uint)(nil)

	if len(f.gpuMarkerOffsets) > 0 {
		cMarkerOffsets = (*C.int)(unsafe.Pointer(&f.gpuMarkerOffsets[0]))
	}

	if len(markerData) > 0 {
		cMarkerData = (*C.uint)(unsafe.Pointer(&markerData[0]))
	}
	/*
		fmt.Println("CuEVM Debug: callData length", len(callData))
		fmt.Println("CuEVM Debug: dataOffsets length", len(dataOffsets))
		fmt.Println("CuEVM Debug: dataSizes length", len(dataSizes))
		fmt.Println("CuEVM Debug: values length", len(values))
		fmt.Println("CuEVM Debug: validCallCount", validCallCount)
		fmt.Print("CuEVM Debug: dataOffsets & dataSizes: ")
		for i := 0; i < validCallCount; i++ {
			fmt.Printf("[%d]:(%d,%d) ", i, dataOffsets[i], dataSizes[i])
		}
		fmt.Println() // Add a newline at the end
		/// print all call data
		if len(callData) > 0 {
			fmt.Print("CuEVM Debug: callData: ")
			for i, b := range callData {
				if i > 0 && i%4 == 0 {
					fmt.Print(" ")
				}
				fmt.Printf("%02x", b)
			}
			fmt.Println() // Add a newline at the end of the printed data
		}
	*/
	cValues := (*C.uchar)(nil)

	cResult := C.process_batch_transactions(
		(*C.uint64_t)(unsafe.Pointer(&f.gpuBlockNumbers[0])),
		(*C.uint64_t)(unsafe.Pointer(&f.gpuTimeStamps[0])),
		(*C.uchar)(unsafe.Pointer(&f.gpuFromAddr[0])),
		(*C.uchar)(unsafe.Pointer(&toAddr[0])),
		cValues,
		(*C.uchar)(unsafe.Pointer(&callData[0])), C.uint32_t(len(callData)),
		(*C.uint)(unsafe.Pointer(&f.gpuDataOffsets[0])),
		(*C.uint)(unsafe.Pointer(&f.gpuDataSizes[0])),
		cMarkerOffsets,
		cMarkerData,
		C.uint32_t(len(markerData)),
		C.uint32_t(txBatchSize),
		C.uint32_t(sequenceLength),
		C.uint32_t(f.currentRandomSeed), // default random seed is C.uint32_t(f.loopCounter),
	)

	// fmt.Println("CuEVM Debug: C function returned", cResult)
	//    BranchInfoEntry* new_branch_info;
	// uint32_t num_new_branch;
	// BugInfoEntry* new_bug_info;
	// uint32_t num_new_bug;
	// StorageInfoEntry* new_storage_info;
	// uint32_t num_new_storage;
	if cResult != nil {
		numResults := int(cResult.num_results)

		// Only create the Go structure if we have results to return
		if numResults > 0 {
			gpuResult := &coverage.GPUExecutionResult{
				NewCoverageThreadIdx: make([][]uint32, numResults),
				NewCoverageIds:       make([][]uint32, numResults),
				NewBugThreadIdx:      make([][]uint32, numResults),
				NewBugPCs:            make([][]uint32, numResults),
				NewBugTypes:          make([][]uint32, numResults),
				NewStorageThreadIdx:  make([][]uint32, numResults),
				NewStorageIds:        make([][]uint32, numResults),
			}

			// Process each batch result directly
			results := unsafe.Slice(cResult.results, numResults)
			for i := 0; i < numResults; i++ {
				result := results[i]

				// Process coverage data
				numNewCoverage := int(result.num_new_branch)
				if numNewCoverage > 0 && result.new_branch_info != nil {
					// Convert C pointer to Go slice before indexing
					branchInfoSlice := unsafe.Slice(result.new_branch_info, numNewCoverage)
					for j := 0; j < numNewCoverage; j++ {
						fmt.Println("CuEVM Debug: GPU %d: new_coverage[%d]: %d", i, j, branchInfoSlice[j].branch_thread_idx)
						branchInfo := branchInfoSlice[j]
						gpuResult.NewCoverageThreadIdx[i] = append(gpuResult.NewCoverageThreadIdx[i], uint32(branchInfo.branch_thread_idx))
					}
				}

				// Process bug data
				numNewBugs := int(result.num_new_bug)
				if numNewBugs > 0 {
					if result.new_bug_info != nil {
						// Convert C pointer to Go slice before indexing
						bugInfoSlice := unsafe.Slice(result.new_bug_info, numNewBugs)
						for j := 0; j < numNewBugs; j++ {
							bugInfo := bugInfoSlice[j]
							gpuResult.NewBugThreadIdx[i] = append(gpuResult.NewBugThreadIdx[i], uint32(bugInfo.bug_thread_idx))
							gpuResult.NewBugPCs[i] = append(gpuResult.NewBugPCs[i], uint32(bugInfo.bug_id>>16))
							gpuResult.NewBugTypes[i] = append(gpuResult.NewBugTypes[i], uint32(bugInfo.bug_id&0xFFFF))
						}
					}
				}

				// Process storage data
				numNewStorage := int(result.num_new_storage)
				if numNewStorage > 0 {
					if result.new_storage_info != nil {
						// Convert C pointer to Go slice before indexing
						storageInfoSlice := unsafe.Slice(result.new_storage_info, numNewStorage)
						for j := 0; j < numNewStorage; j++ {
							storageInfo := storageInfoSlice[j]
							gpuResult.NewStorageThreadIdx[i] = append(gpuResult.NewStorageThreadIdx[i], uint32(storageInfo.storage_thread_idx))
						}
					}
				}
			}
			// debug printing
			// fmt.Println("CuEVM Debug: GPU execution results")
			// fmt.Println(gpuResult.DebugString())

			// fmt.Println("CuEVM Debug: GPU execution results end")
			// Free the C memory
			C.free_simplified_gpu_result(cResult)
			return gpuResult, nil
		}
		// TODO: free other C memory
		// Free the C memory
		C.free_simplified_gpu_result(cResult)
		fmt.Println("CuEVM Debug: GPU execution returned no results")
	} else {
		fmt.Println("CuEVM Debug: C function returned nil result")
	}
	return nil, nil
}

// prepareAndProcessChainStateInGPU extracts the chain state and block header information and sends it to the GPU
func (f *Fuzzer) prepareAndProcessChainStateInGPU(testChain *chain.TestChain) error {
	if f.GPUchainInitiated {
		fmt.Println("\n\n GPU chain already initiated, skipping JSON dump state\n\n")
		result := C.process_json_state_gpu(nil, C.uint(f.config.Fuzzing.Workers), true, C.uint(f.skipSequenceSize), nil, nil, 0)
		if result != 0 {
			return fmt.Errorf("C++ GPU state processing returned error code: %d", result)
		}
		return nil
	}
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
			f.BaseValueSet().AddAddress(addr)

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
	var stateDump ethstate.Dump
	// Get the current state from the chain
	state := testChain.State()
	// Get raw state dump
	dumpConfig := &ethstate.DumpConfig{
		SkipCode:    false,
		SkipStorage: false,

		OnlyWithAddresses: false,
		Start:             nil,
		Max:               1000,
	}

	// eth_state, _ := state.(*ethstate.StateDB)
	// Check for ForkStateDb first (since it embeds StateDB)
	if forkState, ok := state.(*ethstate.ForkStateDb); ok {
		fmt.Println("Using ForkStateDb")
		// ForkStateDb embeds StateDB, so we can access the embedded StateDB
		stateDump = forkState.StateDB.RawDump(dumpConfig)
	} else if ethState, ok := state.(*ethstate.StateDB); ok {
		fmt.Println("Using vanilla StateDB")
		stateDump = ethState.RawDump(dumpConfig)
	} else {
		return fmt.Errorf("unsupported state type: %T", state)
	}

	// Convert state dump to JSON format
	stateJSON := convertStateToJSON(&stateDump, testChain.Head().Header, worker)
	// CuEVM debug, to be deleted
	// fmt.Println("CuEVM Debug: stateJSON", stateJSON)
	// os.Exit(0)
	// Call C function to process the JSON state
	cJSON := C.CString(stateJSON)
	defer C.free(unsafe.Pointer(cJSON))

	fmt.Println("CuEVM Debug: valueset ")
	f.BaseValueSet().SyncArrays()
	// Sort for deterministic order
	addressSet := f.BaseValueSet().Addresses()
	integerSet := f.BaseValueSet().Integers()

	for _, addr := range addressSet {
		fmt.Println("CuEVM Debug: address", addr.Hex())
	}

	for _, integer := range integerSet {
		fmt.Println("CuEVM Debug: integer", hex.EncodeToString(integer.Bytes()))
	}

	sendersList := make([]string, len(f.senders))
	for i, addr := range f.senders {
		sendersList[i] = addr.Hex()
	}
	for _, sender := range sendersList {
		fmt.Println("CuEVM Debug: sender", sender)
	}
	// groupConstantsByTypeHex groups slither constants by type and converts values to hex strings as required.
	groupedConstants := groupConstantsByTypeHex(addressSet, integerSet)
	groupedConstants["sender"] = sendersList
	constantsBytes, err := json.Marshal(groupedConstants)
	var constantJSON *C.char
	if err != nil {
		constantJSON = C.CString("{}") // fallback to empty object if marshal fails
	} else {
		constantJSON = C.CString(string(constantsBytes))
	}
	f.addressConstants = groupedConstants["address"]
	f.integerConstants = groupedConstants["integer"]

	// create address index map
	for i, addr := range addressSet {
		f.addressIndexMap[addr] = uint8(i)
	}
	fmt.Println("CuEVM Debug: addressIndexMap", f.addressIndexMap)

	// fmt.Println("\n\nCuEVM Debug: constantJSON", string(constantsBytes))
	// fmt.Println("\n\n")

	defer C.free(unsafe.Pointer(constantJSON))

	cFlattenedMarkers := (*C.uint)(nil)
	if len(f.staticABIFlattenedMarkers) > 0 {
		cFlattenedMarkers = (*C.uint)(unsafe.Pointer(&f.staticABIFlattenedMarkers[0]))
	}
	// create markers data for static aBI methods

	// fmt.Println("CuEVM Debug: flattened markerData")
	// for _, marker := range f.staticABIFlattenedMarkers {
	// 	fmt.Println("CuEVM Debug: marker", marker)
	// }

	// CuEVM debug June 27, change the num_instances calculation
	result := C.process_json_state_gpu(cJSON, C.uint(f.config.Fuzzing.Workers*f.skipSequenceSize), false, C.uint(f.skipSequenceSize), constantJSON,
		cFlattenedMarkers,
		C.uint(len(f.staticABIFlattenedMarkers)),
	)

	// Check the result
	if result != 0 {
		return fmt.Errorf("C++ GPU state processing returned error code: %d", result)
	}

	f.GPUchainInitiated = true
	f.numInstancesPerDevice = int(C.get_num_instances_per_device())
	fmt.Println("CuEVM Debug: numInstancesPerDevice", f.numInstancesPerDevice)
	return nil
}

// convertStateToJSON converts a state dump to JSON string compatible with CuEVM's expected format
func convertStateToJSON(stateDump *ethstate.Dump, blockHeader *types.Header, worker *FuzzerWorker) string {
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

	// CuEVM debug, to be deleted
	// Extract transaction data from first element of each sequence
	// for i := 0; i < len(f.workers); i++ {
	// 	for j := 0; j < len(f.workers[i].callSequenceElements); j++ {
	// 		for k := 0; k < len(f.workers[i].callSequenceElements[j]); k++ {
	// 			fmt.Println("CuEVM Debug CPU: worker", i, "sequence", j, "element", k, "call", f.workers[i].callSequenceElements[j][k])
	// 		}
	// 	}
	// }

	// Process state data from our base test chain for GPU processing
	if len(f.workers) > 0 && f.workers[0] != nil && f.workers[0].chain != nil {
		err := f.prepareAndProcessChainStateInGPU(f.workers[0].chain)
		if err != nil {
			f.logger.Warn("Failed to prepare state data for GPU", err)
		}
	}
	// CuEVM May version, send back the idx in all sequence elements for seed update.
	txBatchSizeGPU := f.sequencesPerCPUWorker * f.numCPUWorkers * f.skipSequenceSize
	txBatchSizeCPU := f.sequencesPerCPUWorker * f.numCPUWorkers // we dont have to skip sequence for CPU
	sequenceLength := f.config.Fuzzing.CallSequenceLength
	gpuResults, err := f.runTransactionsGPU(f.workers, txBatchSizeGPU, sequenceLength)
	// fmt.Println("CuEVM Debug: gpuResults", gpuResults.DebugString(), "err", err)
	// fmt.Println("CuEVM Debug: markerOffsets", markerOffsets)
	// fmt.Println("CuEVM Debug: txBatchSize", txBatchSize)

	if err == nil {
		bigIntWeightValue := big.NewInt(max(10, int64((f.loopCounter+1)*f.sequencesPerCPUWorker*f.numCPUWorkers/10)))
		f.assertion_test_provider.GPUPostCallTest(f.workers, gpuResults, f.gpuMarkerOffsets, bigIntWeightValue)

		// add all call sequences to corpus
		for batchIdx := 0; batchIdx < len(gpuResults.NewCoverageThreadIdx); batchIdx++ {
			// fmt.Println("\n\nCuEVM Debug: batchIdx", batchIdx, "\n\n")
			for idx := 0; idx < len(gpuResults.NewCoverageThreadIdx[batchIdx]); idx++ {
				// translate from gpu idx to cpu idx (no skip sequence)
				rawIdx := int(gpuResults.NewCoverageThreadIdx[batchIdx][idx]) / f.skipSequenceSize
				workerIdx := rawIdx / f.sequencesPerCPUWorker
				sequenceIdx := rawIdx % f.sequencesPerCPUWorker
				elementIdx := batchIdx
				// fmt.Println("CuEVM Debug: batchIdx", batchIdx, "raw gpu idx", int(gpuResults.NewCoverageIndices[batchIdx][idx]), "rawIdx", rawIdx, "workerIdx", workerIdx, "sequenceIdx", sequenceIdx, "elementIdx", elementIdx)
				// Create a sequence from element 0 to elementIdx
				fullSequence := make(calls.CallSequence, elementIdx+1)
				for i := 0; i <= elementIdx; i++ {

					fullSequence[i], _ = f.workers[workerIdx].callSequenceElements[sequenceIdx][i].Clone()

					// Warning i is element index in a squence
					// Need to reply i when reconstructing the sequence
					markerOffsetIdx := (rawIdx + i*txBatchSizeCPU)
					methodSig := fullSequence[i].Call.DataAbiValues.Method.Sig
					// fmt.Println("CuEVM Debug: markerOffsetIdx", markerOffsetIdx, "methodSig", methodSig)
					var dataMarkers []calls.DataMarker
					if f.gpuMarkerOffsets[markerOffsetIdx] < 0 {
						dataMarkers = f.staticABIMarkers[f.staticABIMarkerIndexMap[methodSig]]
					} else {
						// fmt.Println("CuEVM Debug: markerOffsets[markerOffsetIdx] (sequenceIdx/f.skipSequenceSize)*f.skipSequenceSize", markerOffsets[markerOffsetIdx], "sequenceIdx", sequenceIdx, "i", i)
						dataMarkers = f.workers[workerIdx].callSequenceElements[sequenceIdx][i].Call.DataMarkers
					}
					// fmt.Println("CuEVM Debug: dataMarkers", dataMarkers)
					// dataMarkers := f.workers[workerIdx].callSequenceElements[(sequenceIdx/f.skipSequenceSize)*f.skipSequenceSize][i].Call.DataMarkers
					// fmt.Println("CuEVM Debug: fullSequence[i].Call.Data", hex.EncodeToString(fullSequence[i].Call.Data))
					// mutatedData, mutatedBlockNumber, mutatedBlockTimestamp, mutatedValue := f.restore_mutation(fullSequence[i].Call.Data, dataMarkers, int(gpuResults.NewCoverageIndices[batchIdx][idx]), i)
					mutatedData, mutatedBlockNumber, mutatedBlockTimestamp, mutatedSenderIndex, mutatedValue :=
						fuzzingutils.RestoreMutation(fullSequence[i].Call.Data, dataMarkers, int(gpuResults.NewCoverageThreadIdx[batchIdx][idx]), i,
							fuzzingutils.FuzzerConfig{
								StartSeed:              f.currentRandomSeed,
								BatchSize:              uint32(txBatchSizeGPU),
								NumInstancesPerDevice:  f.numInstancesPerDevice,
								AddressConstants:       f.addressConstants,
								IntegerConstants:       f.integerConstants,
								BlockNumberDelayMax:    60480, // hardcode for now
								BlockTimestampDelayMax: 604800,
								SenderCount:            uint32(len(f.senders)),
							})

					if mutatedBlockNumber >= 0 {
						fullSequence[i].BlockNumberDelay = uint64(mutatedBlockNumber)
					}
					if mutatedBlockTimestamp >= 0 {
						fullSequence[i].BlockTimestampDelay = uint64(mutatedBlockTimestamp)
					}
					if mutatedSenderIndex >= 0 {
						fullSequence[i].Call.From = f.senders[mutatedSenderIndex]
					}
					fullSequence[i].Call.Value = mutatedValue
					var inputValues []any

					if len(mutatedData) >= 4 {
						if fullSequence[i].Call.DataAbiValues.Method.Sig != "CuEVM::fallback()" {
							inputData := mutatedData[4:] // skip the method ID
							inputValues, err = fullSequence[i].Call.DataAbiValues.Method.Inputs.Unpack(inputData)
						} else {
							inputValues, err = fullSequence[i].Call.DataAbiValues.Method.Inputs.Unpack(mutatedData)
						}

					} else {
						fmt.Println("\n\nCuEVM Debug: inputValues empty\n\n")
						inputValues = []any{}
					}
					if err != nil {
						fmt.Println("\n\nCuEVM Debug: unpack error\n\n", err)
						// skip unpack if err occurs
						err = nil

					}
					// fmt.Println("CuEVM debug original data ", hex.EncodeToString(fullSequence[i].Call.Data))
					fullSequence[i].Call.DataAbiValues.InputValues = inputValues
					// fmt.Println("CuEVM Debug: fullSequence[i].Call.DataAbiValues.InputValues", fullSequence[i].Call.DataAbiValues.InputValues)
					fullSequence[i].Call.Data = mutatedData
					// fmt.Println("CuEVM debug mutated value", hex.EncodeToString(mutatedValue.Bytes()))
					// fmt.Println("CuEVM debug mutated value", mutatedValue)
					// fmt.Println("CuEVM debug mutated block number", mutatedBlockNumber)
					// fmt.Println("CuEVM debug mutated block timestamp", mutatedBlockTimestamp)
					// fmt.Println("CuEVM debug mutated data ", hex.EncodeToString(mutatedData))
					// fmt.Println("CuEVM debug new inputValues", inputValues)

					// fmt.Println("CuEVM Debug: Call element", fullSequence[i])
				}
				// fmt.Println("CuEVM Debug: GPU adding sequence to corpus bigIntWeightValue", bigIntWeightValue)
				// fmt.Println("CuEVM Debug: fullSequence", fullSequence)
				// Send sequence to shrink worker for execution and corpus addition
				select {
				case f.shrinkWorker.addSequenceCorpusChan <- AddSequenceCorpusRequest{
					Sequence: fullSequence,
					Weight:   bigIntWeightValue,
				}:
					// Successfully enqueued
				default:
					fmt.Println("addSequenceCorpusChan full, adding sequence directly to corpus")
					err = f.corpus.AddCallSequence(fullSequence, bigIntWeightValue)
				}
				if err != nil {
					return err
				}
			}
		}

	}

	// CuEVM Debug, simulate the run on CPU
	// Now process transaction data for each worker
	/*
		for i := 0; i < len(f.workers); i++ {
			worker := f.workers[i]
			if worker == nil || worker.chain == nil {
				continue
			}

			// Check if we should stop execution
			if utils.CheckContextDone(f.emergencyCtx) || utils.CheckContextDone(f.ctx) {
				break
			}

			// Execute each sequence individually, resetting chain state before each one
			for sequenceIdx, sequence := range worker.callSequenceElements {
				// fmt.Println("CuEVM Debug: sequenceIdx", sequenceIdx, "sequence", sequence)
				// Reset chain to base state before executing this sequence
				err := worker.chain.RevertToBlockIndex(worker.testingBaseBlockIndex)
				if err != nil {
					worker.lastExecutionError = err
					break
				}
				// fmt.Println("CuEVM Debug: worker.chain.RevertToBlockIndex(worker.testingBaseBlockIndex)", worker.chain.RevertToBlockIndex(worker.testingBaseBlockIndex))

				// Execute this single sequence
				_, worker.lastExecutionError = calls.SimulateExecuteCallSequenceGPUWithList(
					worker.chain,
					sequence,
					worker.executionCheckFunc,
				)

				// If there was an error executing this sequence, break out of the sequence loop
				if worker.lastExecutionError != nil {
					f.logger.Warn("Error executing sequence", sequenceIdx, "for worker", i, ":", worker.lastExecutionError)
					break
				}
			}
		}
	*/
	return nil
}

// processWorkersResultsInParallel handles all post-processing logic in parallel
// Returns a boolean indicating if workers should be cancelled and an error if one occurred
func (f *Fuzzer) processWorkersResultsInParallel() (bool, error) {
	var wg sync.WaitGroup
	errChan := make(chan error, f.numCPUWorkers)
	cancelChan := make(chan bool, f.numCPUWorkers)

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
			// if !worker.isNewSequence {
			// 	for i := 0; i < len(worker.pendingShrinkRequests); i++ {
			// 		worker.pendingShrinkRequests[i].RecordResultInCorpus = false
			// 	}
			// }

			// Add any new shrink requests to the worker's list for next iteration
			// fmt.Println("CuEVM Debug: workerIdx", workerIndex, "worker.pendingShrinkRequests", len(worker.pendingShrinkRequests))
			if len(worker.pendingShrinkRequests) > 0 {
				worker.shrinkCallSequenceRequests = append(worker.shrinkCallSequenceRequests, worker.pendingShrinkRequests...)
			}

			// // Reset value set to original
			// worker.valueSet = worker.originalValueSet

			// // Reset chain state
			// if worker.lastExecutionError == nil {
			// 	err := worker.chain.RevertToBlockIndex(worker.testingBaseBlockIndex)
			// 	if err != nil {
			// 		errChan <- err
			// 		return
			// 	}
			// } else {
			// 	// Return any execution error
			// 	errChan <- worker.lastExecutionError
			// 	return
			// }

			// Emit event indicating the worker finished testing a call sequence
			// err := worker.Events.CallSequenceTested.Publish(FuzzerWorkerCallSequenceTestedEvent{
			// 	Worker: worker,
			// })
			// if err != nil {
			// 	errChan <- fmt.Errorf("error returned by an event handler: %v", err)
			// 	return
			// }

			// Update metrics
			// worker.workerMetrics().sequencesTested.Add(worker.workerMetrics().sequencesTested, big.NewInt(1*int64(f.sequencesPerCPUWorker)))
			// worker.workerMetrics().callsTested.Add(worker.workerMetrics().callsTested, big.NewInt(int64(f.sequencesPerCPUWorker*worker.fuzzer.config.Fuzzing.CallSequenceLength)))
			// fmt.Println("CuEVM Debug: worker.workerMetrics().sequencesTested", worker.workerMetrics().sequencesTested)
			// fmt.Println("CuEVM Debug: worker.workerMetrics().callsTested", worker.workerMetrics().callsTested)
			// Check if we've reached the worker reset limit
			// sequencesTested := worker.workerMetrics().sequencesTested.Uint64() / uint64(f.sequencesPerCPUWorker) // div by sequences per cpu worker to check worker reset limit
			// if sequencesTested > uint64(worker.fuzzer.config.Fuzzing.WorkerResetLimit) {
			// Close the chain to free resources
			// GPU workers we will not free the chain, just keep it to run at the end
			// if worker.chain != nil {
			// 	worker.chain.Close()
			// 	worker.chain = nil
			// }
			// worker.workerMetrics().sequencesTested = big.NewInt(0)
			// }
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

// RunAllSequences runs all sequences in the corpus and captures final coverage
func (f *Fuzzer) RunAllSequences() {
	callSequencesToTest := f.corpus.ExtractAllSequences()
	fmt.Println("Medusa_callSequencesToTest:")
	for _, sequence := range callSequencesToTest {
		fmt.Println("Medusa_sequence:", sequence)
	}
	// selectedSender := f.senders[0]
	// fmt.Println("Medusa_pureMethods:", f.workers[0].pureMethods)
	// fmt.Println("Medusa_pureMethods_length:", len(f.workers[0].pureMethods))
	// for _, selectedMethod := range f.workers[0].pureMethods {
	// 	// fmt.Println("Medusa_method:", selectedMethod.Method.Name)
	// 	// Generate fuzzed parameters for the function call
	// 	args := make([]any, len(selectedMethod.Method.Inputs))
	// 	for i := 0; i < len(args); i++ {
	// 		// Create our fuzzed parameters.
	// 		input := selectedMethod.Method.Inputs[i]
	// 		args[i] = valuegeneration.GenerateAbiValue(f.workers[0].sequenceGenerator.config.ValueGenerator, &input.Type)
	// 	}
	// 	// If this is a payable function, generate value to send
	// 	var value *big.Int
	// 	value = big.NewInt(0)
	// 	msg := calls.NewCallMessageWithAbiValueData(selectedSender, &selectedMethod.Address, 0, value, f.config.Fuzzing.TransactionGasLimit, big.NewInt(1), big.NewInt(0), big.NewInt(0), &calls.CallMessageDataAbiValues{
	// 		Method:      &selectedMethod.Method,
	// 		InputValues: args,
	// 	})

	// 	callSequence := calls.CallSequence{calls.NewCallSequenceElement(selectedMethod.Contract, msg, uint64(0), uint64(0))}
	// 	callSequencesToTest = append(callSequencesToTest, callSequence)

	// }

	if len(callSequencesToTest) == 0 {
		f.logger.Info("No sequences in corpus to run for final coverage")
		return
	}

	f.logger.Info("Running all ", colors.Bold, len(callSequencesToTest), colors.Reset, " sequences in corpus for final coverage")

	finalSequenceWorkers := f.numCPUWorkers
	// Distribute sequences across available workers
	sequencesPerWorker := (len(callSequencesToTest) + finalSequenceWorkers - 1) / finalSequenceWorkers

	var wg sync.WaitGroup
	for i := 0; i < finalSequenceWorkers; i++ {

		worker := f.workers[i]
		// Create a simple execution check function just for recording coverage
		worker.executionCheckFunc = func(currentlyExecutedSequence calls.CallSequence) (bool, error) {
			err := f.corpus.CheckSequenceCoverageAndUpdate(currentlyExecutedSequence, worker.getNewCorpusCallSequenceWeight(), true)
			if err != nil {
				return true, err
			}
			return false, nil
		}

		// Calculate this worker's slice of sequences
		startIdx := i * sequencesPerWorker
		endIdx := (i + 1) * sequencesPerWorker
		if endIdx > len(callSequencesToTest) {
			endIdx = len(callSequencesToTest)
		}
		// Skip if no sequences to process
		if startIdx >= len(callSequencesToTest) {
			continue
		}

		// Copy the slice for this goroutine
		workerSequences := callSequencesToTest[startIdx:endIdx]

		wg.Add(1)
		go func(w *FuzzerWorker, sequences []calls.CallSequence) {
			defer wg.Done()

			for _, sequence := range sequences {

				// Revert to base state before executing
				err := w.chain.RevertToBlockIndex(w.testingBaseBlockIndex)
				if err != nil {
					f.logger.Error("Failed to revert chain to base state", err)
					continue
				}
				fmt.Println("CuEVM Debug: sequence")
				for k := 0; k < len(sequence); k++ {
					fmt.Println("CuEVM Debug: sequence[", k, "]", sequence[k])
				}

				_, worker.lastExecutionError = calls.SimulateExecuteCallSequenceGPUWithList(
					worker.chain,
					sequence,
					worker.executionCheckFunc,
				)
			}
		}(worker, workerSequences)
	}

	// Wait for all workers to complete
	wg.Wait()

	// Log final coverage stats
	f.logger.Info("Final coverage: ", colors.Bold, f.corpus.CoverageMaps().BranchesHit(), colors.Reset, " branches hit")
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

	// CuEVM Debug: fixed number of CPU workers
	f.numCPUWorkers = runtime.NumCPU()
	f.GPUchainInitiated = false
	rawSequencesPerWorker := (f.config.Fuzzing.Workers / f.skipSequenceSize) / f.numCPUWorkers

	// Round up to next multiple of skipSequenceSize
	roundedSequencesPerWorker := max(1, rawSequencesPerWorker)
	// roundedSequencesPerWorker := max(f.skipSequenceSize, ((rawSequencesPerWorker+f.skipSequenceSize-1)/f.skipSequenceSize)*f.skipSequenceSize)

	// Update total workers to ensure proper division
	f.config.Fuzzing.Workers = roundedSequencesPerWorker * f.numCPUWorkers

	// Now this will be divisible by skipSequenceSize
	f.sequencesPerCPUWorker = f.config.Fuzzing.Workers / f.numCPUWorkers

	// Size the pre-allocated GPU arrays now that we know the dimensions
	validCallCount := f.sequencesPerCPUWorker * f.numCPUWorkers * f.config.Fuzzing.CallSequenceLength

	f.gpuDataOffsets = make([]uint32, validCallCount*f.skipSequenceSize)
	f.gpuDataSizes = make([]uint32, validCallCount*f.skipSequenceSize)
	f.gpuMarkerOffsets = make([]int32, validCallCount)
	f.gpuFromAddr = make([]uint8, validCallCount*f.skipSequenceSize)
	f.gpuBlockNumbers = make([]uint64, validCallCount*f.skipSequenceSize)
	f.gpuTimeStamps = make([]uint64, validCallCount*f.skipSequenceSize)

	// Pre-allocate call data buffer with a reasonable initial capacity
	// This will grow as needed but reduces initial allocations
	initialCallDataCapacity := validCallCount * 100 // Estimate 100 bytes per call on average
	f.gpuCallDataBuffer = make([]byte, 0, initialCallDataCapacity)

	// fmt.Println("CuEVM Debug: f.sequencesPerCPUWorker", f.sequencesPerCPUWorker, "f.config.Fuzzing.Workers", f.config.Fuzzing.Workers, "f.numCPUWorkers", f.numCPUWorkers)
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
	// f.metrics = newFuzzerMetrics(f.config.Fuzzing.Workers, f.revertReporter.RevertMetricsCh)
	// CuEVM : fixed number of workers
	f.metrics = newFuzzerMetrics(f.numCPUWorkers, f.revertReporter.RevertMetricsCh)

	// Initialize our test cases and providers
	f.testCasesLock.Lock()
	f.testCases = make([]TestCase, 0)
	f.testCasesFinished = make(map[string]TestCase)
	f.testCasesLock.Unlock()

	// fmt.Println("testchain config skipAccountChecks", f.config.Fuzzing.TestChainConfig.SkipAccountChecks)
	// Create our test chain
	baseTestChain, err := f.createTestChain(nil)
	if err != nil {
		f.logger.Error("Failed to create the test chain", err)
		return err
	}

	// Set it up with our deployment/setup strategy defined by the fuzzer.
	f.logger.Info("Setting up test chain")
	f.forkMode = false
	trace, err := f.Hooks.ChainSetupFunc(f, baseTestChain)
	if err != nil {
		if trace != nil {
			f.logger.Error("Failed to initialize the test chain", err, errors.New(trace.Log().ColorString()))
		} else {
			f.logger.Error("Failed to initialize the test chain", err)
		}
		// fmt.Println("Retry with chain fork")
		// f.config.Fuzzing.TestChainConfig.ForkConfig.ForkModeEnabled = true
		// f.config.Fuzzing.TestChainConfig.ForkConfig.RpcUrl = "https://eth.llamarpc.com"
		// f.config.Fuzzing.TestChainConfig.ForkConfig.RpcBlock = 22816200
		// f.config.Fuzzing.TestChainConfig.ForkConfig.PoolSize = 20
		// f.forkMode = true
		// baseTestChain, err = f.createTestChain(nil)
		// trace, err = f.Hooks.ChainSetupFunc(f, baseTestChain)
		// fmt.Println("CuEVM Debug: trace", trace)
		fmt.Println("CuEVM Debug: err", err)
		fmt.Println("CuEVM Debug: pendingEvents", len(f.pendingEvents))
		if err != nil || len(f.pendingEvents) > 0 {
			f.logger.Error("Failed to initialize the test chain with fork, try setting runtime bytecode", err)
			f.config.Fuzzing.TestChainConfig.ForkConfig.ForkModeEnabled = false
			genesisAlloc := make(types.GenesisAlloc)
			for _, event := range f.pendingEvents {
				genesisAlloc[event.Contract.Address] = types.Account{
					Balance: big.NewInt(0),
					Code:    event.Contract.RuntimeBytecode,
					Nonce:   0,
				}
			}

			baseTestChain, err = f.createTestChain(&genesisAlloc)
			fmt.Println("CuEVM Debug: code", hex.EncodeToString(baseTestChain.State().GetCode(f.pendingEvents[0].Contract.Address)))
			fmt.Println("CuEVM Debug: setting runtime bytecode err", err)
			err = nil
		}
		// f.logger.Info("Finished setting up test chain with fork")
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
	f.logger.Info("Fuzzing with ", colors.Bold, f.numCPUWorkers*f.skipSequenceSize*f.sequencesPerCPUWorker, colors.Reset, " GPU workers, ", colors.Bold, f.numCPUWorkers, colors.Reset, " CPU workers, and ", colors.Bold, f.sequencesPerCPUWorker, colors.Reset, " sequences per CPU worker")

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

	// Run the main worker loop
	err = f.spawnWorkersLoop(baseTestChain)
	if err != nil {
		f.logger.Error("Encountered an error in the main fuzzing loop", err)
	}

	// NOTE: After this point, we capture errors but do not return immediately, as we want to exit gracefully.

	// If we have coverage enabled and a corpus directory set, write the corpus. We do this even if we had a
	// previous error, as we don't want to lose corpus entries.
	if f.config.Fuzzing.CoverageEnabled {
		fmt.Println("final corpus size: ", f.corpus.ActiveMutableSequenceCount())
		// Wait for the shrink worker to finish
		close(f.shrinkWorker.addSequenceCorpusChan)
		f.shrinkWorker.shrinkWg.Wait()

		fmt.Println("CuEVM Debug: shrinkWg.Wait() finished")
		// run all sequences in the corpus and capture final coverage
		f.RunAllSequences()
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

	fmt.Println("CuEVM Debug: f.metrics.SequencesTested()", f.metrics.SequencesTested())
	// Print our results on exit.
	f.printExitingResults()

	// print unique PC count for printing to the console
	uniquePCs, err := coverage.GetUniquePCsCount(f.compilations, f.corpus.CoverageMaps(), f.logger, f.config.Fuzzing.DeploymentCodeCoverageEnabled)
	if err != nil {
		f.logger.Error("Failed to get unique PC count", err)
		uniquePCs = 0
	}
	fmt.Println("MEDUSA_UNIQUE_PC_COUNT:", uniquePCs)
	fmt.Println("MEDUSA_TOTAL_TRANSACTIONS:", f.callsTested)
	fmt.Println("MEDUSA_PCS_LOGS:", f.PCsLogs)

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

			// Get all sequences from the corpus
			allSequences := f.corpus.ExtractAllSequences()
			// Write corpus sequences to JSON file
			corpusPath := filepath.Join(coverageReportDir, "corpus.json")
			corpusData, jsonErr := json.Marshal(allSequences)
			if jsonErr == nil {
				if writeErr := os.WriteFile(corpusPath, corpusData, 0644); writeErr == nil {
					f.logger.Info("Corpus sequences saved to: ", colors.Bold, corpusPath, colors.Reset)
				}
			}

			// write assertion test cases to json
			if f.assertion_test_provider != nil {
				allBugReported := f.assertion_test_provider.getAllBugReported()
				allBugReportedPath := filepath.Join(coverageReportDir, "bugs.json")
				allBugReportedData, jsonErr := json.MarshalIndent(allBugReported, "", "  ")
				if jsonErr == nil {
					if writeErr := os.WriteFile(allBugReportedPath, allBugReportedData, 0644); writeErr == nil {
						f.logger.Info("Bug reports (", colors.Bold, len(allBugReported), colors.Reset, " bugs) saved to: ", colors.Bold, allBugReportedPath, colors.Reset)
					} else {
						f.logger.Error("Failed to write bug reports to file", writeErr)
					}
				} else {
					f.logger.Error("Failed to marshal bug reports to JSON", jsonErr)
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
	f.fuzzStartTime = startTime
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

		}
		// if time.Since(f.lastPCsLogMsg) >= timeBetweenPCsLogMsgs {
		start := time.Now()
		totalPCs, err := coverage.GetUniquePCsCount(f.compilations, f.corpus.CoverageMaps(), f.logger, f.config.Fuzzing.DeploymentCodeCoverageEnabled)
		fmt.Println("CuEVM Debug: totalPCs", totalPCs)
		f.PCsLogs = append(f.PCsLogs, totalPCs)
		// This is just for a log message. This shouldn't error but if it does we don't need to exit out
		if err == nil {
			end := time.Now()
			f.lastPCsLogMsg = end
			logBuffer.Append(", total PCs hit: ", colors.Bold, fmt.Sprintf("%v", totalPCs), colors.Reset)
			logBuffer.Append(", time to calculate total PCs hit: ", colors.Bold, fmt.Sprintf("%v", end.Sub(start)), colors.Reset)
		}
		// }
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
		time.Sleep(time.Second * 2)
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

// groupConstantsByTypeHex groups slither constants by type and converts values to hex strings as required.
func groupConstantsByTypeHex(addresses []common.Address, integers []*big.Int) map[string][]string {
	result := make(map[string][]string)

	// precompute 2^256
	two256 := new(big.Int).Lsh(big.NewInt(1), 256)

	for _, c := range addresses {
		result["address"] = append(result["address"], c.Hex())
	}
	for _, c := range integers {
		cMod := new(big.Int).Mod(c, two256)
		b := make([]byte, 32)
		cMod.FillBytes(b)
		hexStr := "0x" + hex.EncodeToString(b)
		result["integer"] = append(result["integer"], hexStr)
	}
	// corner case for empty constants
	if len(result["address"]) == 0 {
		result["address"] = append(result["address"], "0x0000000000000000000000000000000000000000")
	}
	if len(result["integer"]) == 0 {
		result["integer"] = append(result["integer"], "0x0000000000000000000000000000000000000000000000000000000000000000")
	}
	return result
}
