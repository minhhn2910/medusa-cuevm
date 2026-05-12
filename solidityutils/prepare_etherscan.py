#!/usr/bin/env python3
"""
Download verified contract source JSON from Etherscan/BSCScan API for a single address.

Simplified script that fetches contract source code for one contract address
and saves it to a specified JSON file.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests

API_URLS = {
    "eth": "https://api.etherscan.io/v2/api",
    "bsc": "https://api.bscscan.com/api",
}

CHAIN_IDS = {
    "eth": 1,
    "bsc": 56,
}

API_TIMEOUT = 30
API_RETRIES = 5


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Download contract source JSON for a single contract address.")
    parser.add_argument(
        "address",
        help="Contract address (0x...)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Output JSON file path.",
    )
    parser.add_argument(
        "--chain",
        choices=["eth", "bsc"],
        default="eth",
        help="Blockchain to query (eth or bsc). Default: eth",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("ETHERSCAN_API_KEY") or os.getenv("BSCSCAN_API_KEY"),
        help="API key for the explorer (env: ETHERSCAN_API_KEY or BSCSCAN_API_KEY).",
    )
    return parser.parse_args()


def validate_address(address: str) -> str:
    """Validate and normalize Ethereum address."""
    address = address.strip().lower()
    if not address.startswith("0x") or len(address) != 42:
        sys.exit(f"Invalid address format: {address}")
    return address


def fetch_source_json(
    session: requests.Session,
    api_url: str,
    api_key: Optional[str],
    address: str,
    chain_id: int,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Fetch contract source code from explorer API with retries."""
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
    }

    # Only add chainid for Etherscan v2 API
    if "v2" in api_url:
        params["chainid"] = str(chain_id)

    if api_key:
        params["apikey"] = api_key

    last_exc: Optional[Exception] = None
    for attempt in range(1, API_RETRIES + 1):
        try:
            response = session.get(api_url, params=params, timeout=API_TIMEOUT)
            response.raise_for_status()
            payload = response.json()
            return payload, None
        except (requests.RequestException, ValueError) as exc:
            last_exc = exc
            if attempt < API_RETRIES:
                wait = min(2 ** (attempt - 1), 8)
                print(f"Retry {attempt}/{API_RETRIES} after {wait}s due to: {exc}")
                time.sleep(wait)

    return None, f"API error after {API_RETRIES} retries: {last_exc}"


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    """Write JSON payload to file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> int:
    args = parse_args()

    # Validate address
    address = validate_address(args.address)

    # Get API URL and chain ID
    api_url = API_URLS[args.chain]
    chain_id = CHAIN_IDS[args.chain]

    print(f"Fetching source code for {address} on {args.chain.upper()}...")
    print(f"API URL: {api_url}")

    # Fetch contract source
    session = requests.Session()
    payload, error = fetch_source_json(
        session,
        api_url,
        args.api_key,
        address,
        chain_id,
    )

    if payload is None:
        sys.exit(f"Failed to fetch contract: {error}")

    # Check response status
    status = payload.get("status")
    message = payload.get("message")
    result = payload.get("result")

    if status != "1":
        error_msg = result or message or "Unknown error"
        sys.exit(f"Explorer API returned error: {error_msg}")

    # Extract first item if result is an array
    if isinstance(result, list) and len(result) > 0:
        payload = result[0]
        print(f"Extracted first item from result array")

    # Write to output file
    write_json(args.output, payload)
    print(f"✓ Contract source saved to: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
