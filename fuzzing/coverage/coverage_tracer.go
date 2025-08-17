package coverage

import (
	"math/big"
	"math/bits"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa-geth/core/tracing"
	coretypes "github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa-geth/core/vm"
	"github.com/crytic/medusa-geth/eth/tracers"
	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/chain/types"
	"github.com/crytic/medusa/logging"
)

// coverageTracerResultsKey describes the key to use when storing tracer results in call message results, or when
// querying them.
const coverageTracerResultsKey = "CoverageTracerResults"
const coverageTracerResultsKeyLastId = "CoverageTracerResultsLastId"
const coverageTracerResultsKeyMissedId = "CoverageTracerResultsMissedId"
const coverageTracerResultsKeyDistanceBits = "CoverageTracerResultsDistanceBits"
const coverageTracerResultsKeyStorageIds = "CoverageTracerResultsStorageIds"

// GetCoverageTracerResults obtains CoverageMaps stored by a CoverageTracer from message results. This is nil if
// no CoverageMaps were recorded by a tracer (e.g. CoverageTracer was not attached during this message execution).
func GetCoverageTracerResults(messageResults *types.MessageResults) *CoverageMaps {
	// Try to obtain the results the tracer should've stored.
	if genericResult, ok := messageResults.AdditionalResults[coverageTracerResultsKey]; ok {
		if castedResult, ok := genericResult.(*CoverageMaps); ok {
			return castedResult
		}
	}

	// If we could not obtain them, return nil.
	return nil
}

// GetCoverageTracerResultsWithIds obtains coverage data with branch and storage IDs
func GetCoverageTracerResultsWithIds(messageResults *types.MessageResults) (*CoverageMaps, uint32, uint32, uint8, []uint32) {
	var coverageMaps *CoverageMaps
	var lastCoverageId uint32
	var lastMissedId uint32
	var distanceBits uint8
	var storageIds []uint32

	// Get coverage maps
	if genericResult, ok := messageResults.AdditionalResults[coverageTracerResultsKey]; ok {
		if castedResult, ok := genericResult.(*CoverageMaps); ok {
			coverageMaps = castedResult
		}
	}

	// Get last coverage ID
	if genericResult, ok := messageResults.AdditionalResults[coverageTracerResultsKeyLastId]; ok {
		if castedResult, ok := genericResult.(uint32); ok {
			lastCoverageId = castedResult
		}
	}

	// Get last missed ID
	if genericResult, ok := messageResults.AdditionalResults[coverageTracerResultsKeyMissedId]; ok {
		if castedResult, ok := genericResult.(uint32); ok {
			lastMissedId = castedResult
		}
	}

	// Get distance bits
	if genericResult, ok := messageResults.AdditionalResults[coverageTracerResultsKeyDistanceBits]; ok {
		if castedResult, ok := genericResult.(uint8); ok {
			distanceBits = castedResult
		}
	}

	// Get storage IDs
	if genericResult, ok := messageResults.AdditionalResults[coverageTracerResultsKeyStorageIds]; ok {
		if castedResult, ok := genericResult.([]uint32); ok {
			storageIds = castedResult
		}
	}

	return coverageMaps, lastCoverageId, lastMissedId, distanceBits, storageIds
}

// RemoveCoverageTracerResults removes CoverageMaps stored by a CoverageTracer from message results.
func RemoveCoverageTracerResults(messageResults *types.MessageResults) {
	delete(messageResults.AdditionalResults, coverageTracerResultsKey)
}

// Constants for coverage tracking (matching GPU implementation)
const HASHMAP_SIZE = 65536

// DistanceTracker tracks distance for missed branches
type DistanceTracker struct {
	lastDistance *big.Int
}

func NewDistanceTracker() *DistanceTracker {
	return &DistanceTracker{
		lastDistance: big.NewInt(0),
	}
}

func (d *DistanceTracker) RecordDistance(op byte, stack [][]byte) {
	if len(stack) < 2 {
		return
	}

	// Get operands from stack (32-byte values)
	op1 := new(big.Int).SetBytes(stack[0])
	op2 := new(big.Int).SetBytes(stack[1])
	// fmt.Printf("CuEVM Debug distance: op1: %s, op2: %s\n", op1.String(), op2.String())
	// Calculate absolute difference
	distance := new(big.Int)
	if op1.Cmp(op2) >= 0 {
		distance.Sub(op1, op2)
	} else {
		distance.Sub(op2, op1)
	}
	// fmt.Printf("CuEVM Debug distance: distance: %s\n", distance.String())
	// For non-EQ operations, add 1 (matching GPU logic)
	if op != byte(vm.EQ) {
		distance.Add(distance, big.NewInt(1))
	}

	d.lastDistance = distance
}

func (d *DistanceTracker) GetDistanceBits() uint8 {
	if d.lastDistance == nil {
		return 0
	}
	bitLength := d.lastDistance.BitLen()
	// fmt.Printf("CuEVM Debug distance: lastDistance: %s, bitLength: %d\n", d.lastDistance.String(), bitLength)
	if bitLength > 255 {
		return 255
	}
	return uint8(bitLength)
}

// CoverageTracer implements tracers.Tracer to collect information such as coverage maps
// for fuzzing campaigns from EVM execution traces.
type CoverageTracer struct {
	// coverageMaps describes the execution coverage recorded. Call frames which errored are not recorded.
	coverageMaps *CoverageMaps

	// callFrameStates describes the state tracked by the tracer per call frame.
	callFrameStates []*coverageTracerCallFrameState

	// callDepth refers to the current EVM depth during tracing.
	callDepth int

	evmContext *tracing.VMContext

	// nativeTracer is the underlying tracer used to capture EVM execution.
	nativeTracer *chain.TestChainTracer

	// Coverage tracking features (matching GPU implementation)
	lastCoverageId   uint32
	lastMissedId     uint32
	lastDistanceBits uint8
	storageIds       []uint32
	distanceTracker  *DistanceTracker

	// codeHashCache is a cache for values returned by getContractCoverageMapHash,
	// so that this expensive calculation doesn't need to be done every opcode.
	// The [2] array is to differentiate between contract init (0) vs runtime (1),
	// since init vs runtime produces different results from getContractCoverageMapHash.
	// The Hash key is a contract's codehash, which uniquely identifies it.
	codeHashCache [2]map[common.Hash]common.Hash
}

// coverageTracerCallFrameState tracks state across call frames in the tracer.
type coverageTracerCallFrameState struct {
	// Some fields, such as address, are not initialized until OnOpcode is called.
	// initialized tracks whether or not this has happened yet.
	initialized bool

	// create indicates whether the current call frame is executing on init bytecode (deploying a contract).
	create bool

	// pendingCoverageMap describes the coverage maps recorded for this call frame.
	pendingCoverageMap *CoverageMaps

	// lookupHash describes the hash used to look up the ContractCoverageMap being updated in this frame.
	lookupHash *common.Hash

	// lastPC is the most recent PC that has been executed. Used for coverage tracking.
	lastPC uint64

	// address is used by OnOpcode to cache the result of scope.Address(), which is slow.
	// It records the address of the current contract.
	address common.Address

	wasJumpi bool
	// justJumped indicates whether or not the most recent instruction (the one indicated by lastPC) was JUMP/JUMPI.
	justJumped bool
}

// NewCoverageTracer returns a new CoverageTracer.
func NewCoverageTracer() *CoverageTracer {
	tracer := &CoverageTracer{
		coverageMaps:    NewCoverageMaps(),
		callFrameStates: make([]*coverageTracerCallFrameState, 0),
		storageIds:      make([]uint32, 0),
		distanceTracker: NewDistanceTracker(),
		codeHashCache:   [2]map[common.Hash]common.Hash{make(map[common.Hash]common.Hash), make(map[common.Hash]common.Hash)},
	}
	nativeTracer := &tracers.Tracer{
		Hooks: &tracing.Hooks{
			OnTxStart: tracer.OnTxStart,
			OnEnter:   tracer.OnEnter,
			OnExit:    tracer.OnExit,
			OnOpcode:  tracer.OnOpcode,
		},
	}
	tracer.nativeTracer = &chain.TestChainTracer{Tracer: nativeTracer, CaptureTxEndSetAdditionalResults: tracer.CaptureTxEndSetAdditionalResults}

	return tracer
}

// NativeTracer returns the underlying TestChainTracer.
func (t *CoverageTracer) NativeTracer() *chain.TestChainTracer {
	return t.nativeTracer
}

// OnTxStart is called upon the start of transaction execution, as defined by tracers.Tracer.
func (t *CoverageTracer) OnTxStart(vm *tracing.VMContext, tx *coretypes.Transaction, from common.Address) {
	// Reset our call frame states
	t.callDepth = 0
	t.coverageMaps = NewCoverageMaps()
	t.callFrameStates = make([]*coverageTracerCallFrameState, 0)
	t.evmContext = vm

	// Reset coverage tracking fields
	t.lastCoverageId = 0
	t.lastMissedId = 0
	t.lastDistanceBits = 0
	t.storageIds = make([]uint32, 0)
	t.distanceTracker = NewDistanceTracker()
}

// OnEnter initializes the tracing operation for the top of a call frame, as defined by tracers.Tracer.
func (t *CoverageTracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	// Check to see if this is the top level call frame
	isTopLevelFrame := depth == 0

	// Increment call frame depth if it is not the top level call frame
	if !isTopLevelFrame {
		t.callDepth++
	}

	// Create our state tracking struct for this frame.
	t.callFrameStates = append(t.callFrameStates, &coverageTracerCallFrameState{
		create:             typ == byte(vm.CREATE) || typ == byte(vm.CREATE2),
		pendingCoverageMap: NewCoverageMaps(),
	})
}

// OnExit is called after a call to finalize tracing completes for the top of a call frame, as defined by tracers.Tracer.
func (t *CoverageTracer) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	currentCallFrameState := t.callFrameStates[t.callDepth]
	currentCoverageMap := currentCallFrameState.pendingCoverageMap

	// Record the exit in our coverage map
	// We should always be initialized here, but if we aren't then fields like address will be messed up, so we check to be sure
	if currentCallFrameState.initialized && currentCallFrameState.lookupHash != nil {
		var markerXor uint64
		if reverted {
			markerXor = REVERT_MARKER_XOR
		} else {
			markerXor = RETURN_MARKER_XOR
		}
		marker := bits.RotateLeft64(currentCallFrameState.lastPC, 32) ^ markerXor
		_, coverageUpdateErr := currentCoverageMap.UpdateAt(currentCallFrameState.address, *currentCallFrameState.lookupHash, marker)
		if coverageUpdateErr != nil {
			logging.GlobalLogger.Panic("Coverage tracer failed to update coverage map while tracing state", coverageUpdateErr)
		}
	}

	// Check to see if this is the top level call frame
	isTopLevelFrame := depth == 0

	// Commit all our coverage maps up one call frame.
	var coverageUpdateErr error
	if isTopLevelFrame {
		// Update the final coverage map if this is the top level call frame
		_, coverageUpdateErr = t.coverageMaps.Update(currentCoverageMap)
	} else {
		// Move coverage up one call frame
		_, coverageUpdateErr = t.callFrameStates[t.callDepth-1].pendingCoverageMap.Update(currentCoverageMap)

		// Pop the state tracking struct for this call frame off the stack and decrement the call depth
		t.callFrameStates = t.callFrameStates[:t.callDepth]
		t.callDepth--
	}
	if coverageUpdateErr != nil {
		logging.GlobalLogger.Panic("Coverage tracer failed to update coverage map during capture end", coverageUpdateErr)
	}

}

// OnOpcode records data from an EVM state update, as defined by tracers.Tracer.
func (t *CoverageTracer) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	// Obtain our call frame state tracking struct
	callFrameState := t.callFrameStates[t.callDepth]

	// Back up these values before we overwrite them
	initialized := callFrameState.initialized
	justJumped := callFrameState.justJumped
	lastPC := callFrameState.lastPC
	wasJumpi := callFrameState.wasJumpi

	// Record some info about where we are
	callFrameState.lastPC = pc
	callFrameState.justJumped = vm.OpCode(op) == vm.JUMP || vm.OpCode(op) == vm.JUMPI
	callFrameState.wasJumpi = vm.OpCode(op) == vm.JUMPI
	if !initialized {
		callFrameState.initialized = true
		callFrameState.address = scope.Address()
	}

	// Track distance for comparison operations (matching GPU logic)
	scopeContext := scope.(*vm.ScopeContext)
	if vm.OpCode(op) == vm.EQ || vm.OpCode(op) == vm.LT || vm.OpCode(op) == vm.GT ||
		vm.OpCode(op) == vm.SLT || vm.OpCode(op) == vm.SGT {
		// fmt.Printf("CuEVM Debug: Comparison operation detected - op: %s, pc: %d\n", vm.OpCode(op).String(), pc)
		// Use len() method to check stack size (it's available)
		if len(scopeContext.Stack.Data()) >= 2 {
			// Get stack values as byte arrays
			stack := make([][]byte, 2)
			val0 := scopeContext.Stack.Back(0).Bytes32()
			val1 := scopeContext.Stack.Back(1).Bytes32()
			stack[0] = val0[:]
			stack[1] = val1[:]
			t.distanceTracker.RecordDistance(op, stack)
			// fmt.Printf("CuEVM Debug: Distance recorded for operation %s\n", vm.OpCode(op).String())
		}
	}

	// Track storage operations (SLOAD/SSTORE)
	if vm.OpCode(op) == vm.SLOAD {
		if len(scopeContext.Stack.Data()) >= 1 {
			slot := scopeContext.Stack.Back(0).Bytes32()
			t.trackStorageOperation(callFrameState.address, common.BytesToHash(slot[:]), false)
		}
	} else if vm.OpCode(op) == vm.SSTORE {
		if len(scopeContext.Stack.Data()) >= 2 {
			slot := scopeContext.Stack.Back(0).Bytes32()
			t.trackStorageOperation(callFrameState.address, common.BytesToHash(slot[:]), true)
		}
	}

	// Track branch coverage for JUMPI operations (matching GPU AFL-style hash)
	// We track when we arrive at a destination after a JUMPI (justJumped == true)
	if wasJumpi {
		// fmt.Printf("CuEVM Debug: Branch detected - lastPC: %d, currentPC: %d, justJumped: %t\n", lastPC, pc, justJumped)

		// Convert address to uint32 account_id (using last 4 bytes)
		account_id := uint32(0)
		if len(callFrameState.address) >= 4 {
			account_id = uint32(callFrameState.address[len(callFrameState.address)-4])<<24 |
				uint32(callFrameState.address[len(callFrameState.address)-3])<<16 |
				uint32(callFrameState.address[len(callFrameState.address)-2])<<8 |
				uint32(callFrameState.address[len(callFrameState.address)-1])
		}

		pc_src := uint32(lastPC)
		pc_dst := uint32(pc)

		// Calculate covered branch hash (AFL-style: (pc_src << 1) ^ pc_dst ^ account_id)
		afl_hash_covered := (pc_src << 1) ^ pc_dst ^ account_id
		afl_hash_covered = afl_hash_covered % HASHMAP_SIZE
		t.lastCoverageId = afl_hash_covered + 1 // +1 to avoid 0

		// fmt.Printf("CuEVM Debug: Coverage ID calculated: %d (pc_src: %d, pc_dst: %d, account_id: 0x%x)\n",
		// 	t.lastCoverageId, pc_src, pc_dst, account_id)

		// For missed branch tracking, we need to know the alternative destination
		// This is a simplified approach - in practice, you'd need static analysis
		// For now, we'll track potential missed branches with distance
		distanceBits := t.distanceTracker.GetDistanceBits()
		// fmt.Printf("CuEVM Debug: Distance bits: %d\n", distanceBits)

		if distanceBits > 0 {
			// Calculate missed branch hash (using a different pc_dst)
			pc_missed := pc_dst ^ 1 // Simple approach: flip lowest bit
			afl_hash_missed := (pc_src << 1) ^ pc_missed ^ account_id
			afl_hash_missed = afl_hash_missed % HASHMAP_SIZE
			t.lastMissedId = afl_hash_missed + 1 // +1 to avoid 0
			t.lastDistanceBits = distanceBits

			// fmt.Printf("CuEVM Debug: Missed ID calculated: %d (pc_missed: %d, distance_bits: %d)\n",
			// 	t.lastMissedId, pc_missed, distanceBits)
		}
	}

	// Now record coverage, if applicable. Otherwise return
	var marker uint64
	if !initialized { // first opcode
		marker = bits.RotateLeft64(ENTER_MARKER_XOR, 32) ^ pc
	} else if justJumped {
		marker = bits.RotateLeft64(lastPC, 32) ^ pc
	} else {
		return
	}

	// We can cast OpContext to ScopeContext because that is the type passed to OnOpcode.
	code := scopeContext.Contract.Code
	isCreate := callFrameState.create
	gethCodeHash := scopeContext.Contract.CodeHash

	cacheArrayKey := 1
	if isCreate {
		cacheArrayKey = 0
	}

	// Obtain our contract coverage map lookup hash.
	if callFrameState.lookupHash == nil {
		if isCreate {
			lookupHash := getContractCoverageMapHash(code, isCreate)
			callFrameState.lookupHash = &lookupHash
		} else {
			lookupHash, cacheHit := t.codeHashCache[cacheArrayKey][gethCodeHash]
			if !cacheHit {
				lookupHash = getContractCoverageMapHash(code, isCreate)
				t.codeHashCache[cacheArrayKey][gethCodeHash] = lookupHash
			}
			callFrameState.lookupHash = &lookupHash
		}
	}

	// Record coverage for this location in our map.
	_, coverageUpdateErr := callFrameState.pendingCoverageMap.UpdateAt(callFrameState.address, *callFrameState.lookupHash, marker)
	if coverageUpdateErr != nil {
		logging.GlobalLogger.Panic("Coverage tracer failed to update coverage map while tracing state", coverageUpdateErr)
	}
}

// trackStorageOperation implements storage tracking logic matching GPU implementation
func (t *CoverageTracer) trackStorageOperation(addr common.Address, slot common.Hash, isWrite bool) {
	// Skip tracking for reentrancy attacker address (matching GPU logic)
	if addr == common.HexToAddress("0xCAFECAFE") {
		return
	}

	// Convert address to account_id (using last 4 bytes)
	account_id := uint32(0)
	if len(addr) >= 4 {
		account_id = uint32(addr[len(addr)-4])<<24 |
			uint32(addr[len(addr)-3])<<16 |
			uint32(addr[len(addr)-2])<<8 |
			uint32(addr[len(addr)-1])
	}

	// Get storage slot as uint16 (using last 2 bytes)
	storage_slot := uint16(slot[30])<<8 | uint16(slot[31])

	// Create storage ID following GPU format:
	// [31:30] 2 bits: is_write (last 2 bits)
	// [29:16] 14 bits: account_id (last 14 bits)
	// [15:0]  16 bits: storage_slot
	write_flag := uint32(0)
	if isWrite {
		write_flag = 1
	}

	storage_id := ((write_flag & 0x3) << 30) |
		((account_id & 0x3FFF) << 16) |
		(uint32(storage_slot) & 0xFFFF)

	// Add to storage IDs list
	t.storageIds = append(t.storageIds, storage_id)
}

// CaptureTxEndSetAdditionalResults can be used to set additional results captured from execution tracing. If this
// tracer is used during transaction execution (block creation), the results can later be queried from the block.
// This method will only be called on the added tracer if it implements the extended TestChainTracer interface.
func (t *CoverageTracer) CaptureTxEndSetAdditionalResults(results *types.MessageResults) {
	// Store our tracer results.
	results.AdditionalResults[coverageTracerResultsKey] = t.coverageMaps

	// Store coverage tracking results
	results.AdditionalResults[coverageTracerResultsKeyLastId] = t.lastCoverageId
	results.AdditionalResults[coverageTracerResultsKeyMissedId] = t.lastMissedId
	results.AdditionalResults[coverageTracerResultsKeyDistanceBits] = t.lastDistanceBits
	results.AdditionalResults[coverageTracerResultsKeyStorageIds] = t.storageIds
	// fmt.Println("CuEVM Debug: CaptureTxEndSetAdditionalResults")
	// fmt.Println("CuEVM Debug: lastCoverageId", t.lastCoverageId)
	// fmt.Println("CuEVM Debug: lastMissedId", t.lastMissedId)
	// fmt.Println("CuEVM Debug: lastDistanceBits", t.lastDistanceBits)
	// fmt.Println("CuEVM Debug: storageIds", t.storageIds)
	// // Debug output: Print coverage tracking results
	// if t.lastCoverageId > 0 || t.lastMissedId > 0 || len(t.storageIds) > 0 {
	// 	fmt.Printf("Coverage Tracer Results:\n")
	// 	if t.lastCoverageId > 0 {
	// 		fmt.Printf("  Last Coverage ID: %d\n", t.lastCoverageId)
	// 	}
	// 	if t.lastMissedId > 0 {
	// 		fmt.Printf("  Last Missed ID: %d (Distance Bits: %d)\n", t.lastMissedId, t.lastDistanceBits)
	// 	}
	// 	if len(t.storageIds) > 0 {
	// 		fmt.Printf("  Storage Operations: %d entries\n", len(t.storageIds))
	// 		for i, storageId := range t.storageIds {
	// 			isWrite := (storageId >> 30) & 0x3
	// 			accountId := (storageId >> 16) & 0x3FFF
	// 			storageSlot := storageId & 0xFFFF
	// 			fmt.Printf("    [%d] Storage ID: 0x%08x (Account: 0x%04x, Slot: 0x%04x, Write: %d)\n",
	// 				i, storageId, accountId, storageSlot, isWrite)
	// 		}
	// 	}
	// 	fmt.Printf("  Coverage Map Branches: %d\n", t.coverageMaps.BranchesHit())
	// 	fmt.Printf("---\n")
	// }
}
