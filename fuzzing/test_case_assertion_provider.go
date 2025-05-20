package fuzzing

import (
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/crytic/medusa/compilation/abiutils"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/fuzzing/config"
	"github.com/crytic/medusa/fuzzing/contracts"
	"github.com/crytic/medusa/fuzzing/coverage"

	"golang.org/x/exp/slices"
)

const (
	CUEVM_INVALID_ERROR_CODE = 0x0B
)

// AssertionTestCaseProvider is am AssertionTestCase provider which spawns test cases for every contract method and
// ensures that none of them result in a failed assertion (e.g. use of the solidity `assert(...)` statement, or special
// events indicating a failed assertion).
type AssertionTestCaseProvider struct {
	// fuzzer describes the Fuzzer which this provider is attached to.
	fuzzer *Fuzzer

	// testCases is a map of contract-method IDs to assertion test cases.GetContractMethodID
	testCases map[contracts.ContractMethodID]*AssertionTestCase

	// testCasesLock is used for thread-synchronization when updating testCases
	testCasesLock sync.Mutex
}

// attachAssertionTestCaseProvider attaches a new AssertionTestCaseProvider to the Fuzzer and returns it.
func attachAssertionTestCaseProvider(fuzzer *Fuzzer) *AssertionTestCaseProvider {
	// Create a test case provider
	t := &AssertionTestCaseProvider{
		fuzzer: fuzzer,
	}

	// Subscribe the provider to relevant events the fuzzer emits.
	fuzzer.Events.FuzzerStarting.Subscribe(t.onFuzzerStarting)
	fuzzer.Events.FuzzerStopping.Subscribe(t.onFuzzerStopping)
	fuzzer.Events.WorkerCreated.Subscribe(t.onWorkerCreated)

	// Add the provider's call sequence test function to the fuzzer.
	fuzzer.Hooks.CallSequenceTestFuncs = append(fuzzer.Hooks.CallSequenceTestFuncs, t.callSequencePostCallTest)
	return t
}

// checkAssertionFailures checks the results of the last call for assertion failures.
// Returns the method ID, a boolean indicating if an assertion test failed, or an error if one occurs.
func (t *AssertionTestCaseProvider) checkAssertionFailures(callSequence calls.CallSequence) (*contracts.ContractMethodID, bool, error) {
	// If we have an empty call sequence, we cannot have an assertion failure
	if len(callSequence) == 0 {
		return nil, false, nil
	}

	// Obtain the contract and method from the last call made in our sequence
	lastCall := callSequence[len(callSequence)-1]
	lastCallMethod, err := lastCall.Method()
	if err != nil {
		return nil, false, err
	}
	methodId := contracts.GetContractMethodID(lastCall.Contract, lastCallMethod)

	// Check if we encountered an enabled panic code.
	// Try to unpack our error and return data for a panic code and verify that that panic code should be treated as a failing case.
	// Solidity >0.8.0 introduced asserts failing as reverts but with special return data. But we indicate we also
	// want to be backwards compatible with older Solidity which simply hit an invalid opcode and did not actually
	// have a panic code.
	lastExecutionResult := lastCall.ChainReference.MessageResults().ExecutionResult
	panicCode := abiutils.GetSolidityPanicCode(lastExecutionResult.Err, lastExecutionResult.ReturnData, true)
	fmt.Printf("CuEVM debug: Assertion check - Error: %v, ReturnData: %v, PanicCode: %v\n",
		lastExecutionResult.Err,
		lastExecutionResult.ReturnData,
		panicCode)
	failure := false
	if panicCode != nil {
		failure = encounteredAssertionFailure(panicCode.Uint64(), t.fuzzer.config.Fuzzing.Testing.AssertionTesting.PanicCodeConfig)
	}

	return &methodId, failure, nil
}

// onFuzzerStarting is the event handler triggered when the Fuzzer is starting a fuzzing campaign. It creates test cases
// in a "not started" state for every method to test discovered in the contract definitions known to the Fuzzer.
func (t *AssertionTestCaseProvider) onFuzzerStarting(event FuzzerStartingEvent) error {
	// Reset our state
	t.testCases = make(map[contracts.ContractMethodID]*AssertionTestCase)

	// Create a test case for every test method.
	for _, contract := range t.fuzzer.ContractDefinitions() {
		// If we're not testing all contracts, verify the current contract is one we specified in our target contracts
		if !t.fuzzer.config.Fuzzing.Testing.TestAllContracts && !slices.Contains(t.fuzzer.config.Fuzzing.TargetContracts, contract.Name()) {
			continue
		}

		for _, method := range contract.AssertionTestMethods {
			// Create local variables to avoid pointer types in the loop being overridden.
			contract := contract
			method := method

			// Create our test case
			testCase := &AssertionTestCase{
				status:         TestCaseStatusNotStarted,
				targetContract: contract,
				targetMethod:   method,
				callSequence:   nil,
			}

			// Add to our test cases and register them with the fuzzer
			methodId := contracts.GetContractMethodID(contract, &method)
			t.testCases[methodId] = testCase
			t.fuzzer.RegisterTestCase(testCase)
		}
	}
	return nil
}

// onFuzzerStopping is the event handler triggered when the Fuzzer is stopping the fuzzing campaign and all workers
// have been destroyed. It clears state tracked for each FuzzerWorker and sets test cases in "running" states to
// "passed".
func (t *AssertionTestCaseProvider) onFuzzerStopping(event FuzzerStoppingEvent) error {
	// Loop through each test case and set any tests with a running status to a passed status.
	for _, testCase := range t.testCases {
		if testCase.status == TestCaseStatusRunning {
			testCase.status = TestCaseStatusPassed
		}
	}
	return nil
}

// onWorkerCreated is the event handler triggered when a FuzzerWorker is created by the Fuzzer. It ensures state tracked
// for that worker index is refreshed and subscribes to relevant worker events.
func (t *AssertionTestCaseProvider) onWorkerCreated(event FuzzerWorkerCreatedEvent) error {
	// Subscribe to relevant worker events.
	event.Worker.Events.ContractAdded.Subscribe(t.onWorkerDeployedContractAdded)
	return nil
}

// onWorkerDeployedContractAdded is the event handler triggered when a FuzzerWorker detects a new contract deployment
// on its underlying chain. It ensures any methods to test which the deployed contract contains are tracked by the
// provider for testing. Any test cases previously made for these methods which are in a "not started" state are put
// into a "running" state, as they are now potentially reachable for testing.
func (t *AssertionTestCaseProvider) onWorkerDeployedContractAdded(event FuzzerWorkerContractAddedEvent) error {
	// If we don't have a contract definition, we can't run tests against the contract.
	if event.ContractDefinition == nil {
		return nil
	}

	// Loop through all methods and find ones for which we have tests
	for _, method := range event.ContractDefinition.CompiledContract().Abi.Methods {
		// Obtain an identifier for this pair
		methodId := contracts.GetContractMethodID(event.ContractDefinition, &method)

		// If we have a test case targeting this contract/method that has not failed, track this deployed method in
		// our map for this worker. If we have any tests in a not-started state, we can signal a running state now.
		t.testCasesLock.Lock()
		testCase, testCaseExists := t.testCases[methodId]
		t.testCasesLock.Unlock()
		if testCaseExists && testCase.Status() == TestCaseStatusNotStarted {
			testCase.status = TestCaseStatusRunning
		}
	}
	return nil
}

// callSequencePostCallTest provides is a CallSequenceTestFunc that performs post-call testing logic for the attached Fuzzer
// and any underlying FuzzerWorker. It is called after every call made in a call sequence. It checks whether invariants
// in methods to test are upheld after each call the Fuzzer makes when testing a call sequence.
func (t *AssertionTestCaseProvider) callSequencePostCallTest(worker *FuzzerWorker, callSequence calls.CallSequence) ([]ShrinkCallSequenceRequest, error) {
	// fmt.Println("CuEVM Debug: callSequencePostCallTest")
	// Create a list of shrink call sequence verifiers, which we populate for each failed test we want a call sequence
	// shrunk for.
	shrinkRequests := make([]ShrinkCallSequenceRequest, 0)

	// Obtain the method ID for the last call and check if it encountered assertion failures.
	methodId, testFailed, err := t.checkAssertionFailures(callSequence)
	if err != nil {
		return nil, err
	}

	// Obtain the test case for this method we're targeting for assertion testing.
	t.testCasesLock.Lock()
	testCase, testCaseExists := t.testCases[*methodId]
	t.testCasesLock.Unlock()
	// fmt.Println("CuEVM Debug: testCase", testCase, "testCaseExists", testCaseExists)
	// Verify a test case exists for this method called (if we're not assertion testing this method, stop)
	if !testCaseExists {
		return shrinkRequests, nil
	}

	// If the test case already failed, skip it
	if testCase.Status() == TestCaseStatusFailed {
		return shrinkRequests, nil
	}

	// If we failed a test, we update our state immediately. We provide a shrink verifier which will update
	// the call sequence for each shrunken sequence provided that fails the test.
	if testFailed {
		// Create a request to shrink this call sequence.
		shrinkRequest := ShrinkCallSequenceRequest{
			TestName:             testCase.Name(),
			CallSequenceToShrink: callSequence,
			VerifierFunction: func(worker *FuzzerWorker, shrunkenCallSequence calls.CallSequence) (bool, error) {
				// Obtain the method ID for the last call and check if it encountered assertion failures.
				shrunkSeqMethodId, shrunkSeqTestFailed, err := t.checkAssertionFailures(shrunkenCallSequence)
				if err != nil {
					return false, err
				}

				// If we encountered assertion failures on the same method, this shrunk sequence is satisfactory.
				return shrunkSeqTestFailed && *methodId == *shrunkSeqMethodId, nil
			},
			FinishedCallback: func(worker *FuzzerWorker, shrunkenCallSequence calls.CallSequence, verbosity config.VerbosityLevel) error {
				// When we're finished shrinking, attach an execution trace to the last call. If verboseTracing is true, attach to all calls.
				if len(shrunkenCallSequence) > 0 {
					_, err = calls.ExecuteCallSequenceWithExecutionTracer(worker.chain, worker.fuzzer.contractDefinitions, shrunkenCallSequence, verbosity)
					if err != nil {
						return err
					}
				}

				// Update our test state and report it finalized.
				testCase.status = TestCaseStatusFailed
				testCase.callSequence = &shrunkenCallSequence
				worker.workerMetrics().failedSequences.Add(worker.workerMetrics().failedSequences, big.NewInt(1))
				worker.Fuzzer().ReportTestCaseFinished(testCase)
				return nil
			},
			RecordResultInCorpus: true,
		}

		// Add our shrink request to our list.
		shrinkRequests = append(shrinkRequests, shrinkRequest)
	}

	return shrinkRequests, nil
}

// GPUPostCallTest provides is a CallSequenceTestFunc that performs post-call testing logic for the attached Fuzzer
// and any underlying FuzzerWorker. It is called after every call made in a call sequence. It checks whether invariants
// in methods to test are upheld after each call the Fuzzer makes when testing a call sequence.
func (t *AssertionTestCaseProvider) GPUPostCallTest(workers []*FuzzerWorker, callSequences []calls.CallSequence, gpuResult *coverage.GPUExecutionResult) (bool, error) {

	var globalShrinkRequestsAdded int32 // 0 for false, 1 for true (atomic)

	/*	var wg sync.WaitGroup

		numWorkers := len(workers)
		if numWorkers == 0 {
			return false, nil // No workers to process
		}
		sequencesPerWorkerBatch := t.fuzzer.sequencesPerCPUWorker
		if sequencesPerWorkerBatch == 0 { // Avoid division by zero if misconfigured
			if len(callSequences) > 0 { // Assign all to the first worker if sequencesPerCPUWorker is 0
				sequencesPerWorkerBatch = len(callSequences)
			} else {
				return false, nil
			}
		}


		for workerIndex := 0; workerIndex < numWorkers; workerIndex++ {
			wg.Add(1)
			go func(currentWorkerIdx int) {
				defer wg.Done()

				worker := workers[currentWorkerIdx]
				// Map to track method IDs for which shrink requests have been added by this worker in this batch.
				methodIDProcessedByThisWorker := make(map[contracts.ContractMethodID]bool)
				// Batch of new shrink requests generated by this worker in this goroutine.
				newShrinkRequestsForThisWorker := make([]ShrinkCallSequenceRequest, 0)

				startIndex := currentWorkerIdx * sequencesPerWorkerBatch
				endIndex := (currentWorkerIdx + 1) * sequencesPerWorkerBatch
				if endIndex > len(callSequences) {
					endIndex = len(callSequences)
				}
				if startIndex >= len(callSequences) { // No sequences for this worker
					return
				}

				for i := startIndex; i < endIndex; i++ {
					callSequence := callSequences[i]
					gpuErrorCode := gpuResult.ErrorCodes[i]

					// Obtain the contract and method from the last call made in our sequence
					if len(callSequence) == 0 {
						// Update metrics even for empty sequence if original logic implies processing
						worker.workerMetrics().callsTested.Add(worker.workerMetrics().callsTested, big.NewInt(1))
						// Assuming 0 gas for an empty/skipped sequence, or apply a default if necessary
						worker.workerMetrics().gasUsed.Add(worker.workerMetrics().gasUsed, new(big.Int).SetUint64(0))
						continue
					}
					lastCall := callSequence[len(callSequence)-1]
					lastCallMethod, err := lastCall.Method()
					if err != nil {
						worker.workerMetrics().callsTested.Add(worker.workerMetrics().callsTested, big.NewInt(1))
						worker.workerMetrics().gasUsed.Add(worker.workerMetrics().gasUsed, new(big.Int).SetUint64(100000)) //todo gas used (default on error)
						continue
					}
					methodId := contracts.GetContractMethodID(lastCall.Contract, lastCallMethod)

					var panicCode *big.Int
					if gpuErrorCode == CUEVM_INVALID_ERROR_CODE {
						panicCode = big.NewInt(1) // Indicates an assertion-like failure from CUEVM
					}

					testFailed := false
					if panicCode != nil {
						testFailed = encounteredAssertionFailure(panicCode.Uint64(), t.fuzzer.config.Fuzzing.Testing.AssertionTesting.PanicCodeConfig)
					}

					t.testCasesLock.Lock()
					testCase, testCaseExists := t.testCases[methodId]
					t.testCasesLock.Unlock()

					if !testCaseExists {
						worker.workerMetrics().callsTested.Add(worker.workerMetrics().callsTested, big.NewInt(1))
						worker.workerMetrics().gasUsed.Add(worker.workerMetrics().gasUsed, new(big.Int).SetUint64(100000)) //todo gas used
						continue
					}

					if testCase.Status() == TestCaseStatusFailed {
						worker.workerMetrics().callsTested.Add(worker.workerMetrics().callsTested, big.NewInt(1))
						worker.workerMetrics().gasUsed.Add(worker.workerMetrics().gasUsed, new(big.Int).SetUint64(100000)) //todo gas used
						continue
					}

					if testFailed {
						if _, exists := methodIDProcessedByThisWorker[methodId]; !exists {
							// Create a request to shrink this call sequence.
							shrinkRequest := ShrinkCallSequenceRequest{
								TestName:             testCase.Name(),
								CallSequenceToShrink: callSequence,
								VerifierFunction: func(shrinkVerifierWorker *FuzzerWorker, shrunkenCallSequence calls.CallSequence) (bool, error) {
									shrunkSeqMethodId, shrunkSeqTestFailed, errVerify := t.checkAssertionFailures(shrunkenCallSequence)
									if errVerify != nil {
										return false, errVerify
									}
									return shrunkSeqTestFailed && methodId == *shrunkSeqMethodId, nil
								},
								FinishedCallback: func(finishedCallbackWorker *FuzzerWorker, shrunkenCallSequence calls.CallSequence, verbosity config.VerbosityLevel) error {
									if len(shrunkenCallSequence) > 0 {
										_, errCb := calls.ExecuteCallSequenceWithExecutionTracer(finishedCallbackWorker.chain, finishedCallbackWorker.fuzzer.contractDefinitions, shrunkenCallSequence, verbosity)
										if errCb != nil {
											return errCb
										}
									}
									testCase.status = TestCaseStatusFailed
									testCase.callSequence = &shrunkenCallSequence
									finishedCallbackWorker.workerMetrics().failedSequences.Add(finishedCallbackWorker.workerMetrics().failedSequences, big.NewInt(1))
									finishedCallbackWorker.Fuzzer().ReportTestCaseFinished(testCase)
									return nil
								},
								RecordResultInCorpus: true,
							}
							newShrinkRequestsForThisWorker = append(newShrinkRequestsForThisWorker, shrinkRequest)
							methodIDProcessedByThisWorker[methodId] = true
							atomic.StoreInt32(&globalShrinkRequestsAdded, 1) // Signal that at least one request was added globally
						}
					}
					worker.workerMetrics().callsTested.Add(worker.workerMetrics().callsTested, big.NewInt(1))
					worker.workerMetrics().gasUsed.Add(worker.workerMetrics().gasUsed, new(big.Int).SetUint64(100000)) //todo gas used
				}

				// Append all new shrink requests for this worker to its pending list.
				// This assumes that appending to worker.pendingShrinkRequests is safe in this context
				// (i.e., only this goroutine appends to this specific worker's list here, and the worker's
				// main loop consumes from it in a synchronized manner).
				if len(newShrinkRequestsForThisWorker) > 0 {
					// TODO: If FuzzerWorker has a mutex for pendingShrinkRequests or an Add method, use it.
					// For now, direct append as per inferred structure.
					worker.pendingShrinkRequests = append(worker.pendingShrinkRequests, newShrinkRequestsForThisWorker...)
				}

			}(workerIndex)
		}

		wg.Wait()
	*/
	finalShrinkRequestsAdded := atomic.LoadInt32(&globalShrinkRequestsAdded) == 1
	fmt.Println("\n\nCuEVM Debug: shrink_requests_added", finalShrinkRequestsAdded)
	return finalShrinkRequestsAdded, nil
}

// encounteredAssertionFailure takes in a panic code and a config.AssertionModesConfig and will determine whether the
// panic code that was hit should be treated as a failing case - which will be determined by whether that panic
// code was enabled in the config. Note that the panic codes are defined in the abiutils package and that this function
// panic if it is provided a panic code that is not defined in the abiutils package.
// TODO: This is a terrible design and a future PR should be made to maintain assertion and panic logic correctly
func encounteredAssertionFailure(panicCode uint64, conf config.PanicCodeConfig) bool {
	// Switch on panic code
	switch panicCode {
	case abiutils.PanicCodeCompilerInserted:
		return conf.FailOnCompilerInsertedPanic
	case abiutils.PanicCodeAssertFailed:
		return conf.FailOnAssertion
	case abiutils.PanicCodeArithmeticUnderOverflow:
		return conf.FailOnArithmeticUnderflow
	case abiutils.PanicCodeDivideByZero:
		return conf.FailOnDivideByZero
	case abiutils.PanicCodeEnumTypeConversionOutOfBounds:
		return conf.FailOnEnumTypeConversionOutOfBounds
	case abiutils.PanicCodeIncorrectStorageAccess:
		return conf.FailOnIncorrectStorageAccess
	case abiutils.PanicCodePopEmptyArray:
		return conf.FailOnPopEmptyArray
	case abiutils.PanicCodeOutOfBoundsArrayAccess:
		return conf.FailOnOutOfBoundsArrayAccess
	case abiutils.PanicCodeAllocateTooMuchMemory:
		return conf.FailOnAllocateTooMuchMemory
	case abiutils.PanicCodeCallUninitializedVariable:
		return conf.FailOnCallUninitializedVariable
	default:
		// If we encounter an unknown panic code, we ignore it
		return false
	}
}
