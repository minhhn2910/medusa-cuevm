package coverage

import (
	"fmt"

	"github.com/crytic/medusa-geth/common"
)

// GPUExecutionResult represents the coverage and return data from GPU execution
type GPUExecutionResult struct {
	ReturnData [][]byte      `json:"returnData"`
	Coverage   []GPUCoverage `json:"coverage"`
	Success    []bool        `json:"success"`
}

// GPUCoverage represents coverage data for a single GPU instance
type GPUCoverage struct {
	Addresses  []string `json:"addresses"`  // Hex strings of contract addresses
	PCCoverage [][]uint `json:"pcCoverage"` // PC coverage flags for each address
}

// UpdateCoverageFromGPU updates the coverage maps with data returned from GPU execution
func (cm *CoverageMaps) UpdateCoverageFromGPU(codeHashMap map[common.Address]common.Hash, gpuCoverage GPUCoverage, isSuccessful bool) (bool, error) {
	// Acquire our thread lock and defer our unlocking for when we exit this method
	cm.updateLock.Lock()
	defer cm.updateLock.Unlock()

	// Track if any coverage was updated
	coverageChanged := false

	// Skip empty coverage data
	if len(gpuCoverage.Addresses) == 0 || len(gpuCoverage.PCCoverage) == 0 {
		return false, nil
	}

	// Process each address and its coverage
	for i, addrStr := range gpuCoverage.Addresses {
		fmt.Println("(cm *CoverageMaps) UpdateCoverageFromGPU addrStr: ", addrStr)
		if i >= len(gpuCoverage.PCCoverage) {
			break // Safety check
		}

		// Convert address string to common.Address
		addr := common.HexToAddress(addrStr)

		// Skip addresses with no coverage
		pcCoverage := gpuCoverage.PCCoverage[i]
		if len(pcCoverage) == 0 {
			continue
		}

		// Get code hash for this address from the provided map
		codeHash, exists := codeHashMap[addr]
		fmt.Println("code hash, addr: ", codeHash, addr)
		if !exists {
			// Skip addresses that don't have a code hash mapping
			continue
		}
		/* todo: continue
		// Create a new CoverageMapBytecodeData for this address's coverage
		coverageData := &CoverageMapBytecodeData{
			executedFlags: pcCoverage,
		}

		// Check if we have a map for this code hash
		mapsByAddress, codeHashExists := cm.maps[codeHash]

		if !codeHashExists {
			fmt.Println("(cm *CoverageMaps) UpdateCoverageFromGPU codeHashExists: ", codeHashExists)
			// Create a new map for this code hash
			mapsByAddress = make(map[common.Address]*ContractCoverageMap)
			cm.maps[codeHash] = mapsByAddress
		}

		// Check if we have a coverage map for this address
		if existingMap, addrExists := mapsByAddress[addr]; addrExists {
			// Update existing coverage map based on execution success
			var changed bool
			var err error
			if isSuccessful {
				changed, err = existingMap.successfulCoverage.update(coverageData)
			} else {
				changed, err = existingMap.revertedCoverage.update(coverageData)
			}
			if err != nil {
				return coverageChanged, err
			}
			coverageChanged = coverageChanged || changed
		} else {
			// Create a new contract coverage map with both fields initialized
			codeCoverageSize := len(pcCoverage)
			newCoverageMap := &ContractCoverageMap{
				successfulCoverage: &CoverageMapBytecodeData{
					executedFlags: make([]uint, codeCoverageSize),
				},
				revertedCoverage: &CoverageMapBytecodeData{
					executedFlags: make([]uint, codeCoverageSize),
				},
			}

			// Update the new coverage map based on execution success
			var changed bool
			var err error
			if isSuccessful {
				changed, err = newCoverageMap.successfulCoverage.update(coverageData)
			} else {
				changed, err = newCoverageMap.revertedCoverage.update(coverageData)
			}
			if err != nil {
				return coverageChanged, err
			}

			// Add to our maps
			mapsByAddress[addr] = newCoverageMap
			coverageChanged = coverageChanged || changed
		}
		*/
	}

	return coverageChanged, nil
}
