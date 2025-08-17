#!/usr/bin/env python3
"""
Simple false positive filter for arithmetic bugs.
Usage: python3 filter_fp.py <contract_name> <source_path> <pc1> <pc2> ...
Outputs: Space-separated list of false positive PCs
"""

import sys
from pathlib import Path

# Add smart-fuzz to path if needed
script_dir = Path(__file__).parent
smart_fuzz_path = script_dir.parent.parent / "smart-fuzz"
if smart_fuzz_path.exists():
    sys.path.insert(0, str(smart_fuzz_path))

try:
    from solc_json_parser.standard_json_parser import StandardJsonParser as SolidityAst
except ImportError:
    SolidityAst = None


def is_false_positive_pc(pc: int, contract_name: str, ast) -> bool:
    """Check if a PC represents a false positive arithmetic bug."""
    try:
        if pc <= 0:
            return True  # Contract-level or invalid PC
            
        frag = ast.source_by_pc(contract_name, pc, deploy=False)
        fragment = frag['fragment'].strip()
        linenums = frag['linenums']
        
        # Calculate line span
        if len(linenums) == 2:
            line_span = linenums[1] - linenums[0]
        else:
            line_span = 0
        
        # Filter multi-line spans (likely function/contract definitions)
        if line_span >= 3:
            return True
            
        # Filter if no arithmetic operators present
        if '+' not in fragment and '-' not in fragment and '*' not in fragment:
            return True
            
        return False
        
    except Exception:
        return True  # If we can't analyze, assume it's a false positive


def main():
    if len(sys.argv) < 4:
        print("Usage: python3 filter_fp.py <contract_name> <source_path> <pc1> <pc2> ...")
        sys.exit(1)
    
    contract_name = sys.argv[1]
    source_path = sys.argv[2]
    solc_version = sys.argv[3]
    pcs = [int(pc) for pc in sys.argv[4:]]
    
    if not SolidityAst:
        print("CuEVM Debug: SolidityAst not found")
        # If no AST parser available, return empty (no false positives detected)
        print("")
        return
    
    try:
        # Create AST
        if source_path.endswith(".json"):
            ast = SolidityAst(source_path, etherscan=True)
        else:
            print("CuEVM Debug: source_path", source_path)
            ast = SolidityAst(source_path, version=solc_version)
        
        # Check each PC
        false_positive_pcs = []
        for pc in pcs:
            if is_false_positive_pc(pc, contract_name, ast):
                false_positive_pcs.append(str(pc))
        
        # Output space-separated list of false positive PCs
        print(" ".join(false_positive_pcs))
        
    except Exception:
        print("CuEVM Debug: Exception", sys.exc_info())
        # If analysis fails, return empty (no false positives detected)
        print("")


if __name__ == "__main__":
    main()