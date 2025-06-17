package calls

import (
	"encoding/json"
	"fmt"
	"reflect"

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
	argData, markers, err := d.packWithMask(d.Method.Inputs, d.InputValues)
	if err != nil {
		return nil, nil, fmt.Errorf("ABI call data packing encountered error: %v", err)
	}
	callData := append(append([]byte{}, d.Method.ID...), argData...)
	// Adjust marker offsets by 4 (method ID length)
	for i := range markers {
		markers[i].Offset += 4
	}
	return callData, markers, nil
}

// packWithMask returns the packed data and a slice of DataMarker for int/uint/address arguments, including those in arrays and tuples.
func (d *CallMessageDataAbiValues) packWithMask(arguments abi.Arguments, args []interface{}) ([]byte, []DataMarker, error) {
	argData, err := arguments.Pack(args...)
	if err != nil {
		return nil, nil, err
	}
	var markers []DataMarker
	// The head section starts at offset 0
	headOffset := 0
	// The tail section starts after the head
	tailOffset := len(arguments) * 32
	// We need to keep track of the current tail offset as we process dynamic types
	tailCursor := tailOffset

	// Helper to recursively walk types/values and collect markers
	var walk func(typ abi.Type, value interface{}, offset int) error
	walk = func(typ abi.Type, value interface{}, offset int) error {
		switch typ.T {
		case abi.IntTy, abi.UintTy:
			markers = append(markers, DataMarker{
				Offset: offset,
				Type:   DataType(typ.Size),
				Length: 32,
			})
		case abi.AddressTy:
			markers = append(markers, DataMarker{
				Offset: offset,
				Type:   DataTypeAddress,
				Length: 32,
			})
		case abi.ArrayTy, abi.SliceTy:
			// Dynamic arrays: value is a slice, static arrays: value is an array
			var arrLen int
			var elems []interface{}
			v := reflect.ValueOf(value)
			arrLen = v.Len()
			for i := 0; i < arrLen; i++ {
				elems = append(elems, v.Index(i).Interface())
			}
			if typ.T == abi.ArrayTy && !isDynamicType(typ) {
				// Static array: elements are in-place
				eleOffset := offset
				for i := 0; i < arrLen; i++ {
					if err := walk(*typ.Elem, elems[i], eleOffset); err != nil {
						return err
					}
					eleOffset += getTypeSize(*typ.Elem)
				}
			} else {
				// Dynamic array: offset points to tail, tail starts with length (32 bytes)
				// The offset in the head points to the start of the array data in the tail
				// The array data in the tail: [length (32 bytes)] [element 0] [element 1] ...
				// The offset argument is the offset in the head (where the 32-byte offset is stored)
				// We need to calculate the actual offset in the packed data for each element
				// The tailCursor points to the start of this array's data
				arrayDataOffset := tailCursor
				tailCursor += 32 + arrLen*32 // 32 for length, 32 per element (assume element is 32 bytes)
				for i := 0; i < arrLen; i++ {
					eleOffset := arrayDataOffset + 32 + i*32
					if err := walk(*typ.Elem, elems[i], eleOffset); err != nil {
						return err
					}
				}
			}
		case abi.TupleTy:
			// Tuple: value is a struct or tuple, walk each field
			v := reflect.ValueOf(value)
			fieldOffset := offset
			for i, elemType := range typ.TupleElems {
				fieldValue := v.Field(i).Interface()
				if err := walk(*elemType, fieldValue, fieldOffset); err != nil {
					return err
				}
				fieldOffset += getTypeSize(*elemType)
			}
		}
		return nil
	}

	// Walk each argument in the head
	for i, arg := range arguments {
		t := arg.Type
		value := args[i]
		if isDynamicType(t) {
			// For dynamic types, the head contains a 32-byte offset to the tail
			// The actual data is in the tail, which we track with tailCursor
			// We'll process the tail after the head
			continue
		}
		if err := walk(t, value, headOffset); err != nil {
			return nil, nil, err
		}
		headOffset += getTypeSize(t)
	}
	// Now process dynamic types in the tail
	headOffset = 0
	for i, arg := range arguments {
		t := arg.Type
		value := args[i]
		if isDynamicType(t) {
			if err := walk(t, value, tailOffset); err != nil {
				return nil, nil, err
			}
			tailOffset += getTypeSize(t)
		}
		headOffset += getTypeSize(t)
	}
	return argData, markers, nil
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
