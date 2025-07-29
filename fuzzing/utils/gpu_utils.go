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
}

const (
	a                                     = 1664525
	c                                     = 1013904223
	m                                     = 0xFFFFFFFF
	CHANCE_TO_TAKE_INTEGER_FROM_CONSTANTS = 10
	CHANCE_TO_CREATE_NEW_INTEGER          = 2
	CHANCE_TO_CREATE_NEW_ADDRESS          = 0
	CHANCE_TO_SKIP_MUTATE                 = 50
	CHANCE_TO_SMALL_DELTA                 = 5
	VALUE_MUTATE_INT32                    = 7
	// VALUE_CHANCE_TO_STOP_INT_32           = 30

	ELEMENT_ADDRESS_TYPE = 1
	ELEMENT_VALUE_TYPE   = 2
	ELEMENT_BOOL_TYPE    = 3
)

// MutateByteArray mutates a byte array in-place, starting at data[0]
func MutateByteArray(data []byte, elementLength, byteLength uint32, seed uint32, createNew bool, integerConstants []string) uint32 {
	seed = (a*seed + c) % m
	mutatedByte := seed % (byteLength + 1)
	if createNew {
		seed = (a*seed + c) % m
		randomChance := seed % 100
		if randomChance <= CHANCE_TO_TAKE_INTEGER_FROM_CONSTANTS && len(integerConstants) > 0 {
			seed = (a*seed + c) % m
			randomIndex := seed % uint32(len(integerConstants))
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
				// Copy bytes from the constants starting at the right position
				start := int(elementLength - byteLength)
				for i := start; i < int(elementLength) && i-start < len(integerConstantBytes); i++ {
					data[i] = integerConstantBytes[i]
				}
			}
		} else {
			for i := 0; i < int(elementLength-mutatedByte); i++ {
				data[i] = 0
			}
		}
	}
	start := int(elementLength - mutatedByte)
	for i := 0; i < int(mutatedByte); i++ {
		seed = (a*seed + c) % m
		data[start+i] = byte(seed & 0xFF)
	}
	return seed
}

// MutateBlockValues mutates block number and timestamp values
// return seed, blockNumber, blockTimestamp, sender index
func MutateBlockValues(seed uint32, blockNumberDelayMax, blockTimestampDelayMax uint32, senderCount uint32) (uint32, int64, int64, int32) {
	seed = (a*seed + c) % m
	randomChance := seed % 100
	if randomChance <= CHANCE_TO_SKIP_MUTATE {
		return seed, -1, -1, -1 // Return -1 values to indicate no mutation
	}

	seed = (a*seed + c) % m
	blockNumber := seed % blockNumberDelayMax

	seed = (a*seed + c) % m
	blockTimestamp := seed % blockTimestampDelayMax

	if blockTimestamp == 0 {
		blockNumber = 0
	} else {
		blockNumber = blockNumber % blockTimestamp
	}

	seed = (a*seed + c) % m
	senderIndex := seed % senderCount

	return seed, int64(blockNumber), int64(blockTimestamp), int32(senderIndex)
}

// MutateValue mutates a big.Int value following the CUDA logic
func MutateValue(seed uint32, value *big.Int) uint32 {
	seed = (a*seed + c) % m
	randomChance := seed % 100
	if randomChance <= CHANCE_TO_SKIP_MUTATE {
		return seed
	}

	// Build value word by word, matching CUDA's value->words[i] = seed
	words := make([]uint32, VALUE_MUTATE_INT32)
	for i := 0; i < VALUE_MUTATE_INT32; i++ {
		seed = (a*seed + c) % m
		words[i] = seed
		// fmt.Println("CuEVM Debug: value word", i, "seed", seed)
		seed = (a*seed + c) % m
		randomChance = seed % 100
		// if randomChance <= VALUE_CHANCE_TO_STOP_INT_32 {
		// 	// fmt.Println("CuEVM Debug: stopping at seed", seed)
		// 	break
		// }
	}

	// Convert words to big.Int (little-endian: words[0] is least significant)
	value.SetUint64(0)
	for i := len(words) - 1; i >= 0; i-- {
		if words[i] != 0 {
			value.Lsh(value, 32)
			value.Add(value, big.NewInt(int64(words[i])))
		}
	}

	return seed
}

// RestoreMutation applies mutation to transaction data following the CUDA logic
func RestoreMutation(data []byte, dataMarkers []calls.DataMarker, sequenceIdx, elementIdx int, fuzzerConfig FuzzerConfig) ([]byte, int64, int64, int32, *big.Int) {

	seed := fuzzerConfig.StartSeed + uint32(elementIdx)*fuzzerConfig.BatchSize + uint32(sequenceIdx) + uint32(sequenceIdx)/uint32(fuzzerConfig.NumInstancesPerDevice)
	// fmt.Println("CuEVM Debug: fuzzerConfig", fuzzerConfig)
	// fmt.Println("CuEVM Debug: sequenceIdx", sequenceIdx, "elementIdx", elementIdx, "seed", seed)
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

	for _, marker := range dataMarkers {
		elementOffset := int(marker.Offset)
		elementType := int(marker.Type)
		elementLength := uint32(marker.Length)

		// Handle value mutation
		if elementType == ELEMENT_VALUE_TYPE {
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
			seed = (a*seed + c) % m
			slice[31] = byte(seed % 2)
			continue
		}

		seed = (a*seed + c) % m
		randomChance := seed % 100
		if randomChance <= CHANCE_TO_SKIP_MUTATE {
			// fmt.Println("CuEVM Debug: skipping mutate, seed", seed)
			if elementType > 7 {
				// mutate the marker data
				seed = (a*seed + c) % m
				randomChance = seed % 100
				if randomChance <= CHANCE_TO_SMALL_DELTA {
					// do small delta mutation
					seed = MutateByteArray(slice, elementLength, 1, seed, false, fuzzerConfig.IntegerConstants)
				}
			}
			continue
		}

		if elementType > 7 {
			byteLength := uint32(elementType) / 8
			// fmt.Println("CuEVM Debug: mutating byte array, seed", seed)
			seed = (a*seed + c) % m
			createNew := (seed % CHANCE_TO_CREATE_NEW_INTEGER) == 0
			// fmt.Println("CuEVM Debug: createNew", createNew)

			seed = MutateByteArray(slice, elementLength, byteLength, seed, createNew, fuzzerConfig.IntegerConstants)
		} else if elementType == ELEMENT_ADDRESS_TYPE { // address
			seed = (a*seed + c) % m
			randomChance := seed % 100
			if randomChance <= CHANCE_TO_CREATE_NEW_ADDRESS {
				seed = MutateByteArray(slice, 32, 20, seed, true, fuzzerConfig.AddressConstants)
			} else {
				seed = (a*seed + c) % m
				if len(fuzzerConfig.AddressConstants) > 0 {
					randomIndex := seed % uint32(len(fuzzerConfig.AddressConstants))
					addressConstant := fuzzerConfig.AddressConstants[randomIndex]
					addressConstantBytes, err := hex.DecodeString(addressConstant[2:]) // remove 0x prefix
					if err == nil {
						// Copy the address bytes (last 20 of 32 bytes)
						copy(slice[12:32], addressConstantBytes)
					}
				}
			}
		}
	}

	return mutated, mutatedBlockNumber, mutatedBlockTimestamp, mutatedSenderIndex, mutatedValue
}
