#!/usr/bin/env python3
"""
Filter and extract bugs from the bugs.json output file.
Extract source line information using PC values and contract names.
"""

import json
import os
import sys
from typing import Dict, Any, List
from operator import itemgetter

# Add smart-fuzz to path if needed
script_dir = os.path.dirname(os.path.abspath(__file__))
smart_fuzz_path = os.path.join(script_dir, "..", "..", "smart-fuzz")
if os.path.exists(smart_fuzz_path):
    sys.path.insert(0, smart_fuzz_path)

try:
    from solc_json_parser.combined_json_parser import CombinedJsonParser as SolidityAst
except ImportError as e:
    print(f"Error importing solc_json_parser: {e}")
    print("Please ensure smart-fuzz dependencies are available")
    sys.exit(1)


def load_bugs_json(bugs_file: str) -> List[Dict]:
    """Load bugs from bugs.json file."""
    try:
        with open(bugs_file, 'r') as f:
            bugs = json.load(f)
        print(f"Loaded {len(bugs)} bugs from {bugs_file}")
        return bugs
    except Exception as e:
        print(f"Error loading bugs file {bugs_file}: {e}")
        return []


def load_medusa_config(config_file: str) -> Dict:
    """Load medusa configuration to get contract and source file info."""
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        return config
    except Exception as e:
        print(f"Error loading medusa config {config_file}: {e}")
        return {}


def extract_source_info_from_pc(pc: int, contract_name: str, ast: SolidityAst) -> Dict:
    """
    Extract source line information from PC using SolidityAst.
    
    Args:
        pc: Program counter value
        contract_name: Name of the contract
        ast: Pre-constructed SolidityAst object
        
    Returns:
        Dictionary with source information or None if extraction fails
    """
    try:
        if pc > 0:
            # Get source fragment from PC
            frag = ast.source_by_pc(contract_name, pc, deploy=False)
            fragment, linenums, source_path_from_ast = itemgetter('fragment', 'linenums', 'source_path')(frag)
            
            # Determine line number range
            if len(linenums) == 2:
                line_start, line_end = linenums[0], linenums[1]
            else:
                line_start = line_end = linenums[0]
            
            return {
                'line_number': [line_start, line_end],
                'fragment': fragment.strip(),
                'source_path': source_path_from_ast,
                'pc_mapped': True
            }
        else:
            # PC is 0, try to get contract-level info
            contract = ast.contract_by_name(contract_name)
            return {
                'line_number': [contract.line_num[0], contract.line_num[1]],
                'fragment': f"contract {contract_name}",
                'source_path': ast.file_path,
                'pc_mapped': False
            }
            
    except Exception as ex:
        print(f"Error mapping source for contract {contract_name}, PC {pc}: {ex}")
        return {
            'line_number': [0, 0],
            'fragment': "Unable to map source",
            'source_path': ast.file_path if hasattr(ast, 'file_path') else "unknown",
            'pc_mapped': False,
            'error': str(ex)
        }


def process_bugs(bugs: List[Dict], medusa_config: Dict) -> List[Dict]:
    """
    Process bugs to extract source line information.
    
    Args:
        bugs: List of bug dictionaries from bugs.json
        medusa_config: Medusa configuration dictionary
        
    Returns:
        List of processed bugs with source information
    """
    processed_bugs = []
    
    # Get source file from medusa config
    platform_config = medusa_config.get('compilation', {}).get('platformConfig', {})
    target_file = platform_config.get('target', '')
    compiler_version = platform_config.get('solcVersion', '')
    
    if not target_file:
        print("Warning: No target file found in medusa config")
        return []
    
    # Construct full path to source file
    source_path = os.path.abspath(target_file)
    if not os.path.exists(source_path):
        print(f"Warning: Source file {source_path} not found")
        return []
    
    print(f"Using source file: {source_path}")
    if compiler_version and compiler_version.strip():
        print(f"Using compiler version: {compiler_version}")
    
    # Create AST object once and reuse for all bugs
    try:
        if compiler_version and compiler_version.strip():
            ast = SolidityAst(source_path, compiler_version)
        else:
            ast = SolidityAst(source_path)
        print("Successfully created AST parser")
    except Exception as e:
        print(f"Error creating AST parser: {e}")
        return []
    
    for i, bug in enumerate(bugs):
        try:
            # Extract bug information
            bug_pc = bug.get('bugPC', 0)
            bug_type = bug.get('bugType', 'Unknown')
            contract_name = bug.get('bugContractName', '')
            bug_time = bug.get('bugTime', '0')
            bug_id = bug.get('id', f'bug_{i}')
            method = bug.get('method', '')
            
            if not contract_name:
                print(f"Warning: No contract name for bug {i}")
                continue
            
            # Extract source information using reusable AST object
            source_info = extract_source_info_from_pc(bug_pc, contract_name, ast)
            
            # Create processed bug entry
            processed_bug = {
                'id': bug_id,
                'bug_type': bug_type,
                'contract_name': contract_name,
                'method': method,
                'pc': bug_pc,
                'time': float(bug_time) if bug_time.replace('.', '').isdigit() else 0.0,
                'line_number': source_info['line_number'],
                'fragment': source_info['fragment'],
                'source_path': source_info['source_path'].split('/')[-1],
                'pc_mapped': source_info['pc_mapped']
            }
            
            # Include error information if present
            if 'error' in source_info:
                processed_bug['mapping_error'] = source_info['error']
            
            # Include original call sequence for reference
            processed_bug['call_sequence'] = bug.get('callSequence', [])
            
            processed_bugs.append(processed_bug)
            
        except Exception as e:
            print(f"Error processing bug {i}: {e}")
            continue
    
    return processed_bugs


def write_output(processed_bugs: List[Dict], output_file: str = None):
    """Write processed bugs to output file or stdout."""
    output_data = {
        "summary": {
            "total_bugs": len(processed_bugs),
            "bugs_with_line_mapping": len([b for b in processed_bugs if b.get('pc_mapped', False)]),
            "bugs_with_errors": len([b for b in processed_bugs if 'mapping_error' in b])
        },
        "bugs": processed_bugs
    }
    
    if output_file:
        try:
            with open(output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"Results written to {output_file}")
        except Exception as e:
            print(f"Error writing output file {output_file}: {e}")
    else:
        print(json.dumps(output_data, indent=2))


def main():
    """Main function to handle command line arguments."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Extract bug line mappings from bugs.json using medusa config"
    )
    parser.add_argument(
        'bugs_file',
        help='Path to bugs.json file'
    )
    parser.add_argument(
        'medusa_config',
        help='Path to medusa configuration JSON file'
    )
    parser.add_argument(
        '-o', '--output',
        help='Path to output JSON file (optional, prints to stdout if not provided)'
    )
    
    args = parser.parse_args()
    
    # Check input files exist
    if not os.path.exists(args.bugs_file):
        print(f"Error: Bugs file {args.bugs_file} does not exist")
        sys.exit(1)
        
    if not os.path.exists(args.medusa_config):
        print(f"Error: Medusa config file {args.medusa_config} does not exist")
        sys.exit(1)
    
    # Load input files
    bugs = load_bugs_json(args.bugs_file)
    medusa_config = load_medusa_config(args.medusa_config)
    
    if not bugs:
        print("No bugs to process")
        sys.exit(1)
        
    if not medusa_config:
        print("Could not load medusa configuration")
        sys.exit(1)
    
    # Process bugs
    processed_bugs = process_bugs(bugs, medusa_config)
    
    if not processed_bugs:
        print("No bugs could be processed")
        sys.exit(1)
    
    # Write output
    write_output(processed_bugs, args.output)
    
    print(f"Successfully processed {len(processed_bugs)} bugs")


if __name__ == "__main__":
    main()

