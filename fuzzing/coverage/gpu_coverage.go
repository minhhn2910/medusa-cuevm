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
	Addresses       []string   `json:"addresses"`       // Hex strings of contract addresses
	BranchCoverages [][]uint64 `json:"branchCoverages"` // PC coverage flags for each address
}

// UpdateCoverageFromGPU updates the coverage maps with data returned from GPU execution
func (cm *CoverageMaps) UpdateCoverageFromGPU(codeHashMap map[common.Address]common.Hash, gpuCoverage GPUCoverage, isSuccessful bool) (bool, error) {
	fmt.Println("(cm *CoverageMaps) UpdateCoverageFromGPU")
	fmt.Println("gpuCoverage: ", gpuCoverage)
	fmt.Println("isSuccessful: ", isSuccessful)
	// Acquire our thread lock and defer our unlocking for when we exit this method
	cm.updateLock.Lock()
	defer cm.updateLock.Unlock()

	// Track if any coverage was updated
	coverageChanged := false

	// Skip empty coverage data
	if len(gpuCoverage.Addresses) == 0 || len(gpuCoverage.BranchCoverages) == 0 {
		return false, nil
	}

	// Process each address and its coverage
	for i, addrStr := range gpuCoverage.Addresses {
		fmt.Println("(cm *CoverageMaps) UpdateCoverageFromGPU addrStr: ", addrStr)
		if i >= len(gpuCoverage.BranchCoverages) {
			break // Safety check
		}

		// Convert address string to common.Address
		addr := common.HexToAddress(addrStr)

		// Skip addresses with no coverage
		branchCoverage := gpuCoverage.BranchCoverages[i]
		if len(branchCoverage) == 0 {
			continue
		}

		// Get code hash for this address from the provided map
		codeHash, exists := codeHashMap[addr]
		fmt.Println("code hash, addr: ", codeHash, addr)
		if !exists {
			// Skip addresses that don't have a code hash mapping
			continue
		}

		// Create a new contract coverage map for this GPU coverage data
		coverageMapToMerge := &ContractCoverageMap{
			executedMarkers: make(map[uint64]uint64),
		}

		// Convert the PC coverage array into a marker->count map
		for _, pc := range branchCoverage {
			coverageMapToMerge.executedMarkers[uint64(pc)]++
		}

		// If a coverage map lookup for this code hash doesn't exist, create the mapping
		mapsByAddress, codeHashExists := cm.maps[codeHash]
		if !codeHashExists {
			mapsByAddress = make(map[common.Address]*ContractCoverageMap)
			cm.maps[codeHash] = mapsByAddress
		}

		// If a coverage map for this address already exists, update it
		// Otherwise, set it to the new coverage map
		if existingCoverageMap, addrExists := mapsByAddress[addr]; addrExists {
			changed, err := existingCoverageMap.update(coverageMapToMerge)
			if err != nil {
				return coverageChanged, err
			}
			coverageChanged = coverageChanged || changed
		} else {
			mapsByAddress[addr] = coverageMapToMerge
			coverageChanged = coverageChanged || (coverageMapToMerge.executedMarkers != nil)
		}
	}

	return coverageChanged, nil
}
