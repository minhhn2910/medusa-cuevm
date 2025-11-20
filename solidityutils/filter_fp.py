#!/usr/bin/env python3
"""
Simple false positive filter for arithmetic bugs.
Usage: python3 filter_fp.py <contract_name> <source_path> <solc_version> <pc:type> ...
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

# Bug type constants (matching Go constants)
CuEVM_INTEGER_BUG = 0x01
CuEVM_INTEGER_ADD = 0x11
CuEVM_INTEGER_SUB = 0x12
CuEVM_INTEGER_MUL = 0x13

BUG_TYPE_NAMES = {
    CuEVM_INTEGER_BUG: "INTEGER_BUG",
    CuEVM_INTEGER_ADD: "ADD",
    CuEVM_INTEGER_SUB: "SUB",
    CuEVM_INTEGER_MUL: "MUL",
}


def is_false_positive_pc(pc: int, bug_type: int, contract_name: str, ast) -> bool:
    """Check if a PC represents a false positive arithmetic bug based on bug type."""
    try:
        if pc <= 0:
            return True  # Contract-level or invalid PC

        frag = ast.source_by_pc(contract_name, pc, deploy=False)
        fragment = frag["fragment"].strip()
        linenums = frag["linenums"]

        print(
            f"CuEVM Debug: PC={pc}, Type={BUG_TYPE_NAMES.get(bug_type, bug_type)}, Fragment='{fragment}'",
            file=sys.stderr,
        )

        # Calculate line span
        if len(linenums) == 2:
            line_span = linenums[1] - linenums[0]
        else:
            line_span = 0

        # Filter multi-line spans (likely function/contract definitions)
        if line_span >= 3:
            return True
        print(f"CuEVM Debug: fragment={fragment}", bug_type)
        # Filter based on bug type and fragment content
        if bug_type == CuEVM_INTEGER_ADD:
            # ADD bug should have + or add in fragment
            if "+" not in fragment and "add" not in fragment.lower():
                return True
        elif bug_type == CuEVM_INTEGER_SUB:
            # SUB bug should have - or sub in fragment
            if "-" not in fragment and "sub" not in fragment.lower():
                return True
        elif bug_type == CuEVM_INTEGER_MUL:
            # MUL bug should have * or mul in fragment
            if "*" not in fragment and "mul" not in fragment.lower():
                return True
        else:
            # For generic INTEGER_BUG, check for any arithmetic operator
            if "+" not in fragment and "-" not in fragment and "*" not in fragment:
                return True

        print(f"CuEVM Integer bug found: PC={pc}, type={bug_type}, fragment={fragment}")
        return False

    except Exception:
        return True  # If we can't analyze, assume it's a false positive


def main():
    if len(sys.argv) < 4:
        print("Usage: python3 filter_fp.py <contract_name> <source_path> <solc_version> <pc:type> ...")
        sys.exit(1)

    contract_name = sys.argv[1]
    source_path = sys.argv[2]
    solc_version = sys.argv[3]

    # Parse PC:TYPE pairs
    bugs = []
    for arg in sys.argv[4:]:
        pc_str, type_str = arg.split(":")
        bugs.append((int(pc_str), int(type_str)))

    if not SolidityAst:
        print("CuEVM Debug: SolidityAst not found", file=sys.stderr)
        # If no AST parser available, return empty (no false positives detected)
        print("")
        return

    try:
        # Create AST
        if source_path.endswith(".json"):
            ast = SolidityAst(source_path, etherscan=True)
        else:
            print(f"CuEVM Debug: source_path={source_path}", file=sys.stderr)
            ast = SolidityAst(source_path, version=solc_version)

        # Check each PC with its bug type
        false_positive_pcs = []
        for pc, bug_type in bugs:
            if is_false_positive_pc(pc, bug_type, contract_name, ast):
                false_positive_pcs.append(str(pc))
        print("*" * 80)
        # Output space-separated list of false positive PCs
        print(" ".join(false_positive_pcs))

    except Exception:
        print(f"CuEVM Debug: Exception {sys.exc_info()}", file=sys.stderr)
        # If analysis fails, return all PCs (all false positives detected)
        print(" ".join(str(pc) for pc, _ in bugs))


if __name__ == "__main__":
    main()
