package calls

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/crytic/medusa-geth/accounts/abi"
	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa-geth/crypto"
	"github.com/crytic/medusa/fuzzing/valuegeneration"
)

// CallMessageDataAbiValues describes a CallMessage Data field which is represented by ABI input argument values.
// This is represented at runtime by an abi.Method and its input values.
// Note: The data may be serialized. When deserializing, the Resolve method must be called to resolve the abi.Method
// and transform the encoded input data into compatible input values for the method.
type CallMessageDataAbiValues struct {
	// Method defines the ABI method definition used to pack input argument values.
	Method *abi.Method

	// InputValues represents the ABI packable input argument values to use alongside the Method to produce the call
	// data.
	InputValues []any

	// methodName stores the name of Method when decoding from JSON. The Method will be resolved using this internal
	// reference when Resolve is called.
	//
	// TODO: Note, this field is deprecated and should be removed after methodSignature is adopted for some time.
	//  This will help transition old corpuses in the meantime.
	methodName string

	// methodSignature stores the function prototype which is used to calculate the method ID. This is human-readable,
	// and easily editable, so it is used in favor of the method ID derived from it.
	//
	// The Method will be resolved using this internal reference when Resolve is called.
	methodSignature string

	// encodedInputValues stores the raw encoded input values when decoding from JSON. The actual InputValues will be
	// decoded using this and the resolved Method once Resolve is called.
	encodedInputValues []any
}

// callMessageDataAbiValuesMarshal is used as an internal struct to represent JSON serialized data for
// CallMessageDataAbiValues.
type callMessageDataAbiValuesMarshal struct {
	MethodName         string `json:"methodName,omitempty"`
	MethodSignature    string `json:"methodSignature"`
	EncodedInputValues []any  `json:"inputValues"`
}

// Clone creates a copy of the given message data and its underlying components, or an error if one occurs.
func (m *CallMessageDataAbiValues) Clone() (*CallMessageDataAbiValues, error) {
	// Create a cloned struct
	clone := &CallMessageDataAbiValues{
		Method:             m.Method,
		InputValues:        nil, // set lower
		methodName:         m.methodName,
		methodSignature:    m.methodSignature,
		encodedInputValues: m.encodedInputValues,
	}

	// If we have a method, clone our input values by packing/unpacking them.
	if m.Method != nil {
		data, err := m.Method.Inputs.Pack(m.InputValues...)
		if err != nil {
			return nil, err
		}

		clone.InputValues, err = m.Method.Inputs.Unpack(data)
		if err != nil {
			return nil, err
		}
	}

	return clone, nil
}

// Resolve takes a previously unmarshalled CallMessageDataAbiValues and resolves all internal data needed for it to be
// used at runtime by resolving the abi.Method it references from the provided contract ABI.
func (d *CallMessageDataAbiValues) Resolve(contractAbi abi.ABI) error {
	// If we have a method signature, try to resolve it by calculating a method ID from this.
	d.Method = nil
	if d.methodSignature != "" {
		methodId := crypto.Keccak256([]byte(d.methodSignature))[:4]
		if resolvedMethod, err := contractAbi.MethodById(methodId); err == nil {
			d.Method = resolvedMethod
		} else {
			return fmt.Errorf("could not resolve method signature '%v'", d.methodSignature)
		}
	}

	// TODO: Deprecated old way of resolving methods. This is left for compatibility with old corpuses, but should be
	//  removed at a later date in favor of methodSignature resolution. It resolves a method by name if it has not been.
	if d.Method == nil {
		if resolvedMethod, ok := contractAbi.Methods[d.methodName]; ok {
			d.Method = &resolvedMethod
		} else {
			return fmt.Errorf("could not resolve method name '%v'", d.methodName)
		}
	}
	d.methodSignature = d.Method.Sig

	// Now that we've resolved the method, decode our encoded input values.
	decodedArguments, err := valuegeneration.DecodeJSONArgumentsFromSlice(d.Method.Inputs, d.encodedInputValues, make(map[string]common.Address))
	if err != nil {
		return fmt.Errorf("error decoding arguments for method '%v': %v", d.methodSignature, err)
	}

	// If we've decoded arguments successfully, set them and clear our encoded arguments as they're no longer needed.
	d.InputValues = decodedArguments
	d.encodedInputValues = nil
	return nil
}

// Pack packs all the ABI argument InputValues into call data for the relevant Method it targets. If this was
// deserialized, Resolve must be called first to resolve necessary runtime data (such as the Method).
func (d *CallMessageDataAbiValues) Pack() ([]byte, error) {
	// If we do not have an ABI method at runtime to serialize this, we will return an error.
	// This may happen when the corpus is being replayed and the ABI of a contract has changed between runs.
	if d.Method == nil {
		return nil, fmt.Errorf("ABI call data packing failed, method definition was not set at runtime")
	}

	// If our ABI method was not set, we can't serialize our data.
	// If our method has a different amount of inputs than we have values, return an error.
	if len(d.Method.Inputs) != len(d.InputValues) {
		return nil, fmt.Errorf("ABI call data packing failed, method definition describes %d input arguments, but %d were provided", len(d.Method.Inputs), len(d.InputValues))
	}

	// Pack the input values
	argData, err := d.Method.Inputs.Pack(d.InputValues...)
	if err != nil {
		return nil, fmt.Errorf("ABI call data packing encountered error: %v", err)
	}

	// Prepend the method ID to the data and return it.
	callData := append(append([]byte{}, d.Method.ID...), argData...)
	return callData, nil
}

// PackWithMask packs all the ABI argument InputValues into call data and generates a list of markers indicating
// the offset, type, and length of each integer or address argument. The mask is a slice of DataMarker.
func (d *CallMessageDataAbiValues) PackWithMask() ([]byte, []DataMarker, error) {
	if d.Method == nil {
		return nil, nil, fmt.Errorf("ABI call data packing failed, method definition was not set at runtime")
	}
	if len(d.Method.Inputs) != len(d.InputValues) {
		return nil, nil, fmt.Errorf("ABI call data packing failed, method definition describes %d input arguments, but %d were provided", len(d.Method.Inputs), len(d.InputValues))
	}

	// This function is a reimplementation of abi.Arguments.Pack, with marker generation added.
	// It works in two passes:
	// 1. Pack all arguments into a single byte slice (`argData`), correctly handling head/tail placement.
	// 2. Walk the type structure and read offsets from the generated `argData` to create markers.

	var head, tail []byte
	var markers []DataMarker

	abiArgs := d.Method.Inputs
	args := d.InputValues

	// add special marker for Value muation
	if d.Method.IsPayable() {
		markers = append(markers, DataMarker{Offset: 0, Type: DataTypeValue, Length: 32})
	}
	// --- Pass 1: Pack arguments and build argData ---

	initialTailOffset := 0
	for _, arg := range abiArgs {
		initialTailOffset += getTypeSize(arg.Type)
	}

	// packSingleArg packs one argument. For dynamic types, it returns just the tail data,
	// stripping the 32-byte offset prefix that `abi.Arguments.Pack` adds for a single arg.
	packSingleArg := func(arg abi.Argument, value interface{}) ([]byte, error) {
		packed, err := abi.Arguments{arg}.Pack(value)
		if err != nil {
			return nil, err
		}
		if isDynamicType(arg.Type) {
			return packed[32:], nil
		}
		return packed, nil
	}

	packedTails := make([][]byte, len(abiArgs))
	currentTailOffset := initialTailOffset
	for i, arg := range abiArgs {
		packed, err := packSingleArg(arg, args[i])
		if err != nil {
			return nil, nil, err
		}

		if isDynamicType(arg.Type) {
			head = append(head, common.LeftPadBytes(big.NewInt(int64(currentTailOffset)).Bytes(), 32)...)
			packedTails[i] = packed // Defer append to tail
			currentTailOffset += len(packed)
		} else {
			head = append(head, packed...)
		}
	}

	for _, packed := range packedTails {
		if packed != nil {
			tail = append(tail, packed...)
		}
	}
	argData := append(head, tail...)

	// --- Pass 2: Generate markers using the final argData ---

	var walkAndMark func(typ abi.Type, offset int)
	walkAndMark = func(typ abi.Type, offset int) {
		switch typ.T {
		case abi.IntTy, abi.UintTy:
			markers = append(markers, DataMarker{Offset: offset, Type: DataType(typ.Size), Length: 32})
		case abi.BoolTy:
			markers = append(markers, DataMarker{Offset: offset, Type: DataTypeBool, Length: 32})
		case abi.AddressTy:
			markers = append(markers, DataMarker{Offset: offset, Type: DataTypeAddress, Length: 32})
		case abi.TupleTy:
			elemOffset := 0
			for _, elemTyp := range typ.TupleElems {
				fieldOffset := offset + elemOffset
				if isDynamicType(*elemTyp) {
					dynamicElemOffset := int(common.BytesToHash(argData[fieldOffset : fieldOffset+32]).Big().Int64())
					walkAndMark(*elemTyp, offset+dynamicElemOffset)
					elemOffset += 32
				} else {
					walkAndMark(*elemTyp, fieldOffset)
					elemOffset += getTypeSize(*elemTyp)
				}
			}
		case abi.SliceTy: // Dynamic Array
			length := int(common.BytesToHash(argData[offset : offset+32]).Big().Int64())
			elemDataStart := offset + 32
			elemSize := getTypeSize(*typ.Elem)
			for i := 0; i < length; i++ {
				elemPos := elemDataStart + (i * elemSize)
				if isDynamicType(*typ.Elem) {
					dynamicElemOffset := int(common.BytesToHash(argData[elemPos : elemPos+32]).Big().Int64())
					walkAndMark(*typ.Elem, offset+dynamicElemOffset)
				} else {
					walkAndMark(*typ.Elem, elemPos)
				}
			}
		case abi.ArrayTy: // Static Array
			elemSize := getTypeSize(*typ.Elem)
			for i := 0; i < typ.Size; i++ {
				walkAndMark(*typ.Elem, offset+(i*elemSize))
			}
		}
	}

	headReadOffset := 0
	for _, arg := range abiArgs {
		if isDynamicType(arg.Type) {
			dynamicOffset := int(common.BytesToHash(argData[headReadOffset : headReadOffset+32]).Big().Int64())
			walkAndMark(arg.Type, dynamicOffset)
			headReadOffset += 32
		} else {
			walkAndMark(arg.Type, headReadOffset)
			headReadOffset += getTypeSize(arg.Type)
		}
	}

	// Adjust all marker offsets by 4 bytes for the method ID.
	if d.Method.Sig != "CuEVM::fallback()" {
		for i := range markers {
			markers[i].Offset += 4
		}
	}
	// CuEVM: decode and pack tempoarily fixed first 4 bytes for fallback and receive

	finalCallData := append(d.Method.ID, argData...)

	return finalCallData, markers, nil
}

// MarshalJSON provides custom JSON marshalling for the struct.
// Returns the JSON marshalled data, or an error if one occurs.
func (d *CallMessageDataAbiValues) MarshalJSON() ([]byte, error) {
	// We must have set an ABI method at runtime to serialize this.
	if d.Method == nil {
		return nil, fmt.Errorf("ABI call data JSON marshaling failed, method definition was not set at runtime")
	}

	// If our ABI method was not set, we can't serialize our data.
	// If our method has a different amount of inputs than we have values, return an error.
	if len(d.Method.Inputs) != len(d.InputValues) {
		return nil, fmt.Errorf("ABI call data JSON marshaling failed, method definition describes %d input arguments, but %d were provided", len(d.Method.Inputs), len(d.InputValues))
	}

	// For every input we have, we serialize it.
	inputValuesEncoded, err := valuegeneration.EncodeJSONArgumentsToSlice(d.Method.Inputs, d.InputValues)
	if err != nil {
		return nil, err
	}

	// Now create our outer struct and marshal all the data and return it.
	marshalData := callMessageDataAbiValuesMarshal{
		MethodSignature:    d.Method.Sig,
		EncodedInputValues: inputValuesEncoded,
	}
	return json.Marshal(marshalData)
}

// UnmarshalJSON provides custom JSON unmarshalling for the struct.
// Returns an error if one occurs.
func (d *CallMessageDataAbiValues) UnmarshalJSON(b []byte) error {
	// Decode our intermediate structure
	var marshalData callMessageDataAbiValuesMarshal
	err := json.Unmarshal(b, &marshalData)
	if err != nil {
		return err
	}

	// Set our data in our actual structure now
	d.methodName = marshalData.MethodName
	d.methodSignature = marshalData.MethodSignature
	d.encodedInputValues = marshalData.EncodedInputValues
	return nil
}

// Helper functions cloned from argument.go for compatibility

// isDynamicType returns true if the type is dynamic
func isDynamicType(t abi.Type) bool {
	if t.T == abi.TupleTy {
		for _, elem := range t.TupleElems {
			if isDynamicType(*elem) {
				return true
			}
		}
		return false
	}
	return t.T == abi.StringTy || t.T == abi.BytesTy || t.T == abi.SliceTy || (t.T == abi.ArrayTy && isDynamicType(*t.Elem))
}

// getTypeSize returns the size of a type in bytes
func getTypeSize(t abi.Type) int {
	if t.T == abi.ArrayTy && !isDynamicType(t) {
		// Static arrays: size = element_size * length
		if t.Size >= 0 {
			return getTypeSize(*t.Elem) * t.Size
		}
	} else if t.T == abi.TupleTy && !isDynamicType(t) {
		// Static tuples: sum of all element sizes
		total := 0
		for _, elem := range t.TupleElems {
			total += getTypeSize(*elem)
		}
		return total
	}
	// For all other types (including dynamic types), return 32 bytes (one slot)
	return 32
}
