package valuegeneration

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/crytic/medusa-geth/common"
	compilationTypes "github.com/crytic/medusa/compilation/types"
)

// SeedFromSlither allows a ValueSet to be seeded from the output of slither.
func (vs *ValueSet) SeedFromSlither(slither *compilationTypes.SlitherResults) {
	// Iterate across all the constants
	vs.AddInteger(big.NewInt(0))
	vs.AddInteger(big.NewInt(1))
	vs.AddInteger(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	vs.AddInteger(new(big.Int).Exp(big.NewInt(10), big.NewInt(19), nil))
	// Add max values for 1, 2, 4, 8, ..., 256 bit unsigned integers
	for bits := 1; bits <= 256; {
		max := new(big.Int).Lsh(big.NewInt(1), uint(bits))
		max.Sub(max, big.NewInt(1))
		fmt.Println("CuEVM Debug: max", max, hex.EncodeToString(max.Bytes()))
		vs.AddInteger(max)
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
