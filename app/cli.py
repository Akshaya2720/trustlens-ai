"""TrustLens AI - Command Line Interface"""

import argparse
import asyncio
import sys
from scripts.diagnose import run_diagnostics


def main():
    parser = argparse.ArgumentParser(description="TrustLens AI CLI")
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    diagnose_parser = subparsers.add_parser("diagnose", help="Run system and API connectivity diagnostics")

    args = parser.parse_args()
    if args.command == "diagnose" or len(sys.argv) == 1:
        asyncio.run(run_diagnostics())
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
