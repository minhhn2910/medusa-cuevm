package valuegeneration

import (
	"math/big"
	"strings"

	"github.com/crytic/medusa-geth/common"
	compilationTypes "github.com/crytic/medusa/compilation/types"
)

// SeedFromSlither allows a ValueSet to be seeded from the output of slither.
func (vs *ValueSet) SeedFromSlither(slither *compilationTypes.SlitherResults) {
	// Iterate across all the constants
	// vs.AddInteger(big.NewInt(0))
	vs.AddInteger(big.NewInt(1))
	vs.AddInteger(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	vs.AddInteger(new(big.Int).Exp(big.NewInt(10), big.NewInt(19), nil))
	// Add max values for 1, 2, 4, 8, ..., 256 bit unsigned integers
	for bits := 4; bits <= 256; {
		max_signed := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
		max_unsigned := new(big.Int).Lsh(big.NewInt(1), uint(bits))
		min_signed := new(big.Int).Neg(max_signed)
		// fmt.Println("CuEVM Debug: max_unsigned", max_unsigned, hex.EncodeToString(max_unsigned.Bytes()))
		// fmt.Println("CuEVM Debug: min_signed", min_signed, hex.EncodeToString(min_signed.Bytes()))
		vs.AddInteger(min_signed)
		vs.AddInteger(max_unsigned)

		if bits <= 64 {
			bits *= 2
		} else {
			bits += 64
		}
	}
	for _, constant := range slither.Constants {
		// Capture uint/int types
		if strings.HasPrefix(constant.Type, "uint") || strings.HasPrefix(constant.Type, "int") {
			var b, _ = new(big.Int).SetString(constant.Value, 10)
			if b != nil {
				vs.AddInteger(b)
				// vs.AddInteger(new(big.Int).Neg(b))
				vs.AddBytes(b.Bytes())
			}
		} else if constant.Type == "bool" {
			// Capture booleans
			// if constant.Value == "False" {
			// 	vs.AddInteger(big.NewInt(0))
			// } else {
			// 	vs.AddInteger(big.NewInt(1))
			// }
		} else if constant.Type == "string" {
			// Capture strings
			vs.AddString(constant.Value)
			vs.AddBytes([]byte(constant.Value))
		} else if constant.Type == "address" {
			// Capture addresses
			var addressBigInt, _ = new(big.Int).SetString(constant.Value, 10)
			vs.AddAddress(common.BigToAddress(addressBigInt))
			vs.AddBytes([]byte(constant.Value))
		}
	}
}
