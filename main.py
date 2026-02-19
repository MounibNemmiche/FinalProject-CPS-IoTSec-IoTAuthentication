"""
IoT Secure Vault Authentication - Main Entry Point

Simulates the mutual authentication protocol from:
"Authentication of IoT Device and IoT Server Using Secure Vaults"

Usage:
    python main.py              # Run demo + experiments
    python main.py --demo       # Run demo only
    python main.py --experiment # Run experiments only
"""

import argparse
import sys

from config import N, M, P
from entities.vault import SecureVault
from entities.device import IoTDevice
from entities.server import IoTServer
from experiments.experiments_comparison import (
    run_all_experiments,
    display_results_table,
    plot_results,
)


def run_demo():
    """Run a single verbose authentication to demonstrate the protocol."""
    print("=" * 60)
    print("  IoT Secure Vault Authentication - Protocol Demo")
    print("=" * 60)
    print(f"\nParameters: N={N} keys, M={M} bytes/key, P={P} keys/challenge\n")

    # --- Setup ---
    print("[Setup] Initializing shared vault...")
    vault = SecureVault(N, M)
    vault.initialize()

    device = IoTDevice("Device_001", vault.clone())
    server = IoTServer()
    server.register_device("Device_001", vault.clone())
    print(f"  Vault: {N} keys of {M} bytes each")
    print(f"  Device ID: Device_001")

    # --- Run multiple authentication sessions ---
    num_sessions = 3
    for session_num in range(1, num_sessions + 1):
        print(f"\n{'-' * 50}")
        print(f"  Session {session_num}/{num_sessions}")
        print(f"{'-' * 50}")

        # Step 1
        m1 = device.step1_initiate()
        print(f"\n  [Step 1] Device -> Server: M1")
        print(f"    Device ID:  {m1['device_id']}")
        print(f"    Session ID: {m1['session_id']}")

        # Step 2
        m2 = server.step2_challenge(m1)
        print(f"\n  [Step 2] Server -> Device: M2")
        print(f"    Challenge C1: {m2['C1']}")
        print(f"    Nonce r1:     {m2['r1'].hex()[:32]}...")

        # Step 3
        m3 = device.step3_respond(m2)
        print(f"\n  [Step 3] Device -> Server: M3")
        print(f"    Ciphertext:   {m3['ciphertext'].hex()[:32]}...")
        print(f"    (encrypted with k1 derived from C1)")

        # Step 4
        m4 = server.step4_verify_and_respond(device.device_id, m3)
        print(f"\n  [Step 4] Server -> Device: M4")
        print(f"    Ciphertext:   {m4['ciphertext'].hex()[:32]}...")
        print(f"    Server verified r1 - device is authenticated!")

        # Step 5
        session_key_device = device.step5_finalize(m4)
        session_key_server = server.get_session_key(device.device_id)
        print(f"\n  [Step 5] Finalization")
        print(f"    Device verified r2 - server is authenticated!")
        print(f"    Session Key (device): {session_key_device.hex()[:32]}...")
        print(f"    Session Key (server): {session_key_server.hex()[:32]}...")

        keys_match = session_key_device == session_key_server
        print(f"    Keys match: {keys_match}")

        if not keys_match:
            print("    ERROR: Session keys do not match!")
            sys.exit(1)

        print(f"    Vault updated for next session.")

    print(f"\n{'=' * 60}")
    print(f"  All {num_sessions} sessions completed successfully!")
    print(f"  Mutual authentication verified. Vaults stay in sync.")
    print(f"{'=' * 60}\n")


def run_experiments():
    """Run the full experiment suite comparing SV vs ECC vs Password."""
    print("=" * 60)
    print("  IoT Authentication - Experiment Suite")
    print("=" * 60)
    print(f"\nParameters: N={N}, M={M}, P={P}")
    print(f"Running experiments...\n")

    results = run_all_experiments()
    display_results_table(results)
    plot_results(results)

    print("\nExperiments completed!")


def main():
    parser = argparse.ArgumentParser(
        description="IoT Secure Vault Authentication Simulation"
    )
    parser.add_argument(
        "--demo", action="store_true", help="Run protocol demo only"
    )
    parser.add_argument(
        "--experiment", action="store_true", help="Run experiments only"
    )
    args = parser.parse_args()

    if args.demo:
        run_demo()
    elif args.experiment:
        run_experiments()
    else:
        # Run both
        run_demo()
        run_experiments()


if __name__ == "__main__":
    main()
