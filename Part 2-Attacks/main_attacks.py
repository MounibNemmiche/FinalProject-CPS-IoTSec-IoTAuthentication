"""
IoT Secure Vault Authentication - Security Attack Simulations

Part 2: Validates the protocol's resistance against cryptographic
and protocol-level attacks.

Usage:
    python "Part 2-Attacks/main_attacks.py"
"""

import os
import sys
from datetime import datetime
from prettytable import PrettyTable

# Add project root to sys.path so we can import entities/ and config.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import N, M, P
from crypto_attacks import BruteForceAttack, VaultKeyRecoveryAttack
from protocol_attacks import ReplayAttack, MITMAttack


class TeeWriter:
    """Duplicates writes to both the terminal and a log file."""

    def __init__(self, log_path: str):
        self._terminal = sys.stdout
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        self._log_file = open(log_path, "w", encoding="utf-8")

    def write(self, message: str) -> int:
        self._terminal.write(message)
        self._log_file.write(message)
        self._log_file.flush()
        return len(message)

    def flush(self) -> None:
        self._terminal.flush()
        self._log_file.flush()

    def close(self) -> None:
        self._log_file.close()


def run_attacks():
    """Run all security attack simulations and display results."""
    print("=" * 60)
    print("  IoT Authentication - Security Attack Simulations")
    print("=" * 60)
    print(f"\nParameters: N={N}, M={M} bytes, P={P}")
    print(f"Running attack simulations...\n")

    attack_results = []
    attack_results.append(BruteForceAttack().run())
    attack_results.append(VaultKeyRecoveryAttack().run())
    attack_results.append(ReplayAttack().run())
    attack_results.append(MITMAttack().run())

    # Summary table
    summary = PrettyTable()
    summary.field_names = ["Attack", "Type", "Status"]
    summary.align["Attack"] = "l"
    summary.align["Type"] = "l"

    for r in attack_results:
        summary.add_row([r["attack"], r["type"], r["status"]])

    print("\n=== Security Attack Summary ===")
    print(summary)

    all_secure = all(r["status"] == "SECURE" for r in attack_results)
    if all_secure:
        print("\nAll attacks FAILED to breach the protocol.")
        print("The Secure Vault protocol resisted all tested attack vectors.")
    else:
        print("\nWARNING: Some attacks breached the protocol!")

    print("\nAttack simulations completed!")


def main():
    # Set up logging: duplicate all print output to a .log file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    project_root = os.path.join(os.path.dirname(__file__), "..")
    log_dir = os.path.join(project_root, "results")
    log_path = os.path.join(log_dir, f"security_attacks_{timestamp}.log")
    tee = TeeWriter(log_path)
    sys.stdout = tee

    try:
        run_attacks()
        tee._terminal.write(f"\nLog file saved to {os.path.relpath(log_path)}\n")
    finally:
        sys.stdout = tee._terminal
        tee.close()


if __name__ == "__main__":
    main()
