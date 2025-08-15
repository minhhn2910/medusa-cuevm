package utils

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/crytic/medusa/fuzzing/calls"
)

type FuzzerConfig struct {
	StartSeed              uint32
	BatchSize              uint32
	NumInstancesPerDevice  int
	AddressConstants       []string
	IntegerConstants       []string
	BlockNumberDelayMax    uint32
	BlockTimestampDelayMax uint32
	SenderCount            uint32
	IsReentrancySender     bool
	IsRandomSender         bool
}

const (
	GLIBC_LCG_A                  = 1103515245
	GLIBC_LCG_C                  = 12345
	CHANCE_TO_CREATE_NEW_ADDRESS = 0
	CHANCE_TO_SKIP_MUTATE        = 50
	CHANCE_TO_SKIP_MUTATE_VALUE  = 25
	VALUE_MUTATE_INT32           = 7

	// AFL-style mutation configuration
	CHANCE_HAVOC_MUTATION = 6
	MAX_HAVOC_STACK       = 3

	ELEMENT_ADDRESS_TYPE = 1
	ELEMENT_VALUE_TYPE   = 2
	ELEMENT_BOOL_TYPE    = 3
)

// AFL mutation types
const (
	MUTATE_BIT_FLIP = iota
	MUTATE_BYTE_FLIP
	MUTATE_ARITHMETIC
	MUTATE_KNOWN_INTEGER
	MUTATE_RANDOM_BYTES
	MUTATE_HAVOC
	MUTATE_TYPE_COUNT
)

// Mutation context to reduce parameter passing
type MutationContext struct {
	Data   []byte
	Length uint32
	Seed   *uint32
}

// Helper: Generate next random number
func nextRand(seed *uint32) uint32 {
	temp := uint64(GLIBC_LCG_A)*uint64(*seed) + GLIBC_LCG_C
	*seed = uint32(temp & 0x7FFFFFFF) // Modulo 2^31
	return *seed                      // 31-bit output
}

// Helper: Get random in range [0, max)
func randRange(seed *uint32, max uint32) uint32 {
	// fmt.Println("CuEVM Debug: randRange seed", *seed, "max", max)
	if max == 0 {
		return 0
	}
	return nextRand(seed) % max
}

// AFL-style mutation functions
func mutateBitFlip(ctx *MutationContext) {
	if ctx.Length == 0 {
		return
	}

	flipSize := uint32(1) << randRange(ctx.Seed, 3) // 1, 2, or 4 bits
	maxBitPos := ctx.Length*8 - flipSize + 1
	bitPos := randRange(ctx.Seed, maxBitPos)

	byteIdx := bitPos / 8
	bitIdx := bitPos % 8

	mask := ((uint32(1) << flipSize) - 1) << bitIdx
	if bitIdx+flipSize <= 8 {
		ctx.Data[byteIdx] ^= byte(mask)
	} else {
		// Handle cross-byte boundary
		ctx.Data[byteIdx] ^= byte(mask & 0xFF)
		if byteIdx+1 < ctx.Length {
			ctx.Data[byteIdx+1] ^= byte((mask >> 8) & 0xFF)
		}
	}
}

func mutateByteFlip(ctx *MutationContext) {
	if ctx.Length == 0 {
		return
	}

	flipSize := uint32(1) << randRange(ctx.Seed, 3) // 1, 2, or 4 bytes
	if flipSize > ctx.Length {
		flipSize = ctx.Length
	}

	startIdx := randRange(ctx.Seed, ctx.Length-flipSize+1)

	for i := uint32(0); i < flipSize; i++ {
		ctx.Data[startIdx+i] ^= 0xFF
	}
}

func mutateArithmetic(ctx *MutationContext) {
	if ctx.Length == 0 {
		return
	}

	delta := 1 + randRange(ctx.Seed, 35) // Small arithmetic delta (1-35)
	isAdd := randRange(ctx.Seed, 2) == 0

	if ctx.Length >= 8 {
		// 64-bit arithmetic with big-endian - target least significant bytes
		startIdx := ctx.Length - 8

		value := (uint64(ctx.Data[startIdx]) << 56) |
			(uint64(ctx.Data[startIdx+1]) << 48) |
			(uint64(ctx.Data[startIdx+2]) << 40) |
			(uint64(ctx.Data[startIdx+3]) << 32) |
			(uint64(ctx.Data[startIdx+4]) << 24) |
			(uint64(ctx.Data[startIdx+5]) << 16) |
			(uint64(ctx.Data[startIdx+6]) << 8) |
			uint64(ctx.Data[startIdx+7])

		if isAdd {
			value += uint64(delta)
		} else {
			value -= uint64(delta)
		}

		ctx.Data[startIdx] = byte((value >> 56) & 0xFF)
		ctx.Data[startIdx+1] = byte((value >> 48) & 0xFF)
		ctx.Data[startIdx+2] = byte((value >> 40) & 0xFF)
		ctx.Data[startIdx+3] = byte((value >> 32) & 0xFF)
		ctx.Data[startIdx+4] = byte((value >> 24) & 0xFF)
		ctx.Data[startIdx+5] = byte((value >> 16) & 0xFF)
		ctx.Data[startIdx+6] = byte((value >> 8) & 0xFF)
		ctx.Data[startIdx+7] = byte(value & 0xFF)

	} else if ctx.Length >= 4 {
		// 32-bit arithmetic with big-endian - target least significant bytes
		startIdx := ctx.Length - 4

		value := (uint32(ctx.Data[startIdx]) << 24) |
			(uint32(ctx.Data[startIdx+1]) << 16) |
			(uint32(ctx.Data[startIdx+2]) << 8) |
			uint32(ctx.Data[startIdx+3])

		if isAdd {
			value += delta
		} else {
			value -= delta
		}

		ctx.Data[startIdx] = byte((value >> 24) & 0xFF)
		ctx.Data[startIdx+1] = byte((value >> 16) & 0xFF)
		ctx.Data[startIdx+2] = byte((value >> 8) & 0xFF)
		ctx.Data[startIdx+3] = byte(value & 0xFF)

	} else {
		// 8-bit arithmetic - target least significant byte
		byteIdx := ctx.Length - 1
		if isAdd {
			ctx.Data[byteIdx] = byte((uint32(ctx.Data[byteIdx]) + delta) & 0xFF)
		} else {
			ctx.Data[byteIdx] = byte((uint32(ctx.Data[byteIdx]) - delta) & 0xFF)
		}
	}
}

func mutateKnownInteger(ctx *MutationContext, integerConstants []string) {
	if ctx.Length == 0 || len(integerConstants) == 0 {
		return
	}

	randomIndex := randRange(ctx.Seed, uint32(len(integerConstants)))
	integerConstant := integerConstants[randomIndex]

	// Decode hex string without "0x" prefix, pad to 32 bytes
	integerConstantBytes := make([]byte, 32)
	decoded, err := hex.DecodeString(integerConstant[2:])
	if err == nil {
		if len(decoded) < 32 {
			copy(integerConstantBytes[32-len(decoded):], decoded)
		} else {
			copy(integerConstantBytes, decoded)
		}

		copyLength := ctx.Length
		if copyLength > 32 {
			copyLength = 32
		}

		for i := uint32(0); i < copyLength; i++ {
			ctx.Data[i] = integerConstantBytes[i]
		}
	}
}

func mutateRandomBytes(ctx *MutationContext) {
	if ctx.Length == 0 {
		return
	}

	startPos := randRange(ctx.Seed, ctx.Length)
	mutatedBytes := 1 + randRange(ctx.Seed, ctx.Length-startPos)

	for i := uint32(0); i < mutatedBytes; i++ {
		ctx.Data[startPos+i] = byte(nextRand(ctx.Seed) & 0xFF)
	}
}

func mutateHavoc(ctx *MutationContext, integerConstants []string) {
	stackCount := 1 + randRange(ctx.Seed, MAX_HAVOC_STACK)

	for i := uint32(0); i < stackCount; i++ {
		mutationType := randRange(ctx.Seed, MUTATE_TYPE_COUNT-1) // Exclude MUTATE_HAVOC

		switch mutationType {
		case MUTATE_BIT_FLIP:
			mutateBitFlip(ctx)
		case MUTATE_BYTE_FLIP:
			mutateByteFlip(ctx)
		case MUTATE_ARITHMETIC:
			mutateArithmetic(ctx)
		case MUTATE_KNOWN_INTEGER:
			mutateKnownInteger(ctx, integerConstants)
		case MUTATE_RANDOM_BYTES:
			mutateRandomBytes(ctx)
		}
	}
}

// AFL-style byte array mutation - matches CUDA afl_mutate_byte_array
func AFLMutateByteArray(data []byte, dataLength, elementBits uint32, seed uint32, integerConstants []string) uint32 {
	if len(data) == 0 || dataLength == 0 {
		return seed
	}

	elementBytes := elementBits / 8
	if elementBytes > dataLength {
		elementBytes = dataLength
	}

	startIdx := dataLength - elementBytes
	ctx := &MutationContext{
		Data:   data[startIdx:dataLength],
		Length: elementBytes,
		Seed:   &seed,
	}

	// Check for havoc mutation first
	if randRange(ctx.Seed, 100) < CHANCE_HAVOC_MUTATION {
		mutateHavoc(ctx, integerConstants)
		return *ctx.Seed
	}

	// Choose regular mutation type
	mutationType := randRange(ctx.Seed, MUTATE_TYPE_COUNT-1) // Exclude MUTATE_HAVOC

	switch mutationType {
	case MUTATE_BIT_FLIP:
		mutateBitFlip(ctx)
	case MUTATE_BYTE_FLIP:
		mutateByteFlip(ctx)
	case MUTATE_ARITHMETIC:
		mutateArithmetic(ctx)
	case MUTATE_KNOWN_INTEGER:
		mutateKnownInteger(ctx, integerConstants)
	case MUTATE_RANDOM_BYTES:
		fallthrough
	default:
		// clear the data
		for i := uint32(0); i < dataLength; i++ {
			data[i] = 0
		}
		// mutate the data
		mutateRandomBytes(ctx)
	}

	return *ctx.Seed
}

// MutateByteArray mutates a byte array in-place, starting at data[0]
// Maintains compatibility with existing code while using AFL-style mutations
func MutateByteArray(data []byte, elementLength, byteLength uint32, seed uint32, createNew bool, integerConstants []string) uint32 {
	// Use AFL-style mutation on the element
	return AFLMutateByteArray(data, elementLength, byteLength*8, seed, integerConstants)
}

// MutateBlockValues mutates block number and timestamp values
// return seed, blockNumber, blockTimestamp, sender index
func MutateBlockValues(seed uint32, blockNumberDelayMax, blockTimestampDelayMax uint32, senderCount uint32) (uint32, int64, int64, int32) {
	if randRange(&seed, 100) <= CHANCE_TO_SKIP_MUTATE {
		// fmt.Println("CuEVM Debug: MutateBlockValues seed returned -1", seed)
		return seed, -1, -1, -1 // Return -1 values to indicate no mutation
	}

	blockNumber := randRange(&seed, blockNumberDelayMax)
	blockTimestamp := randRange(&seed, blockTimestampDelayMax)
	// fmt.Println("CuEVM Debug: MutateBlockValues seed", seed, "blockNumber", blockNumber, "blockTimestamp", blockTimestamp)
	if blockTimestamp == 0 {
		blockNumber = 0
	} else {
		blockNumber = blockNumber % blockTimestamp
	}

	senderIndex := randRange(&seed, senderCount)
	// fmt.Println("CuEVM Debug: senderIndex", senderIndex, "seed", seed)
	return seed, int64(blockNumber), int64(blockTimestamp), int32(senderIndex)
}

// MutateValue mutates a big.Int value following the CUDA logic
func MutateValue(seed uint32, value *big.Int) uint32 {
	if randRange(&seed, 100) <= CHANCE_TO_SKIP_MUTATE_VALUE {
		return seed
	}

	// always mutate at least one value - match CUDA logic exactly
	valueIntType := randRange(&seed, VALUE_MUTATE_INT32-1)
	words := make([]uint32, valueIntType+1) // +1 to ensure at least one word
	for i := 0; i < int(valueIntType+1); i++ {
		words[i] = nextRand(&seed)
	}

	// Convert words to big.Int (little-endian: words[0] is least significant)
	value.SetUint64(0)
	for i := len(words) - 1; i >= 0; i-- {
		value.Lsh(value, 32)
		value.Add(value, big.NewInt(int64(words[i])))
	}

	return seed
}

// RestoreMutation applies mutation to transaction data following the CUDA logic
func RestoreMutation(data []byte, dataMarkers []calls.DataMarker, sequenceIdx, elementIdx int, fuzzerConfig FuzzerConfig) ([]byte, int64, int64, int32, *big.Int) {

	seed := fuzzerConfig.StartSeed + uint32(elementIdx)*fuzzerConfig.BatchSize + uint32(sequenceIdx) + uint32(sequenceIdx)/uint32(fuzzerConfig.NumInstancesPerDevice)
	// fmt.Println("CuEVM Debug: fuzzerConfig", fuzzerConfig)
	// fmt.Println("CuEVM Debug: RestoreMutation sequenceIdx", sequenceIdx, "elementIdx", elementIdx, "seed", seed)
	mutated := make([]byte, len(data))
	copy(mutated, data)

	var mutatedBlockNumber, mutatedBlockTimestamp int64
	var mutatedSenderIndex int32
	mutatedValue := big.NewInt(0)

	// Mutate block values first
	seed, mutatedBlockNumber, mutatedBlockTimestamp, mutatedSenderIndex = MutateBlockValues(seed, fuzzerConfig.BlockNumberDelayMax, fuzzerConfig.BlockTimestampDelayMax, fuzzerConfig.SenderCount)
	// fmt.Println("CuEVM Debug: mutated block number", mutatedBlockNumber)
	// fmt.Println("CuEVM Debug: mutated block timestamp", mutatedBlockTimestamp)
	// fmt.Println("CuEVM Debug: seed", seed)
	// fmt.Println("CuEVM Debug: dataMarkers", dataMarkers)
	var isRandomSender, isReentrancySender bool
	if mutatedSenderIndex == -1 {
		isRandomSender = fuzzerConfig.IsRandomSender
		isReentrancySender = fuzzerConfig.IsReentrancySender
	} else {
		isRandomSender = int32(mutatedSenderIndex) == int32(fuzzerConfig.SenderCount-1)
		isReentrancySender = int32(mutatedSenderIndex) == int32(fuzzerConfig.SenderCount-2)
	}

	for _, marker := range dataMarkers {
		elementOffset := int(marker.Offset)
		elementType := int(marker.Type)
		elementLength := uint32(marker.Length)

		// Handle value mutation
		if elementType == ELEMENT_VALUE_TYPE && !isRandomSender {
			seed = MutateValue(seed, mutatedValue)
			// fmt.Println("CuEVM Debug: mutated value, seed", seed)
			continue
		}
		// input validation and debug
		if (elementOffset + int(elementLength)) > len(mutated) {
			fmt.Println("CuEVM Debug: elementOffset + elementLength is greater than mutated length", elementOffset, elementLength, len(mutated))
			fmt.Println("CuEVM Debug: markers", dataMarkers)
			continue
		}

		slice := mutated[elementOffset:] // operate directly on the sub-slice
		if elementType == ELEMENT_BOOL_TYPE {
			slice[31] = byte(nextRand(&seed) % 2)
			continue
		}

		if randRange(&seed, 100) <= CHANCE_TO_SKIP_MUTATE && elementType != ELEMENT_ADDRESS_TYPE {
			continue
		}

		if elementType > 7 {
			seed = AFLMutateByteArray(slice, elementLength, uint32(elementType), seed, fuzzerConfig.IntegerConstants)

		} else if elementType == ELEMENT_ADDRESS_TYPE { // address

			if len(fuzzerConfig.AddressConstants) > 0 {
				upper_bound := uint32(len(fuzzerConfig.AddressConstants)) - 2
				if isReentrancySender {
					upper_bound += 1
				} else if isRandomSender {
					upper_bound += 2
				}
				randomIndex := randRange(&seed, upper_bound)
				addressConstant := fuzzerConfig.AddressConstants[randomIndex]
				// fmt.Println("CuEVM Debug: randomIndex", randomIndex, "addressConstants", fuzzerConfig.AddressConstants)
				addressConstantBytes, err := hex.DecodeString(addressConstant[2:]) // remove 0x prefix
				if err == nil {
					// Copy the address bytes (last 20 of 32 bytes)
					copy(slice[12:32], addressConstantBytes)
				}
			}
			// }
		}
	}

	return mutated, mutatedBlockNumber, mutatedBlockTimestamp, mutatedSenderIndex, mutatedValue
}
