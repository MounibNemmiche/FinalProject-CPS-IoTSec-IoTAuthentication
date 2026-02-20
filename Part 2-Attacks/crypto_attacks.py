"""
Cryptographic attacks against the Secure Vault protocol.

Adapted from Alessandro's implementation to use the project's
existing entities/ module (no duplicate protocol code).

Attack 1 - Brute Force Key Guessing:
    Attempts to recover the derived key k1 by exhaustive search.
    Tests random M-byte keys against captured M3 ciphertext.

Attack 2 - Vault Key Recovery via GF(2):
    Collects challenge-response pairs and attempts to solve
    for individual vault keys using constraint propagation.
"""

import time

from config import N, M, P, BRUTE_FORCE_ATTEMPTS
from entities.vault import SecureVault
from entities.device import IoTDevice
from entities.server import IoTServer
from entities.crypto_utils import generate_random_key, aes_ecb_decrypt


class BruteForceAttack:
    """Brute force on the temporary derived key k1."""

    def run(self, num_attempts: int = BRUTE_FORCE_ATTEMPTS) -> dict:
        print(f"\n  ATTACK 1: Brute Force Key Guessing")
        print(f"  N={N}, M={M} bytes, P={P}, attempts={num_attempts:,}, key space=2^{M * 8}")

        # Run a legitimate authentication to capture messages
        vault = SecureVault(N, M)
        vault.initialize()
        device = IoTDevice("attacker_target", vault.clone())
        server = IoTServer()
        server.register_device("attacker_target", vault.clone())

        m1 = device.step1_initiate()
        m2 = server.step2_challenge(m1)

        # Capture r1 and the M3 ciphertext (attacker eavesdrops)
        captured_r1 = m2["r1"]
        m3 = device.step3_respond(m2)
        captured_ciphertext = m3["ciphertext"]

        # Attacker tries random keys to decrypt M3
        successes = 0
        start_time = time.perf_counter()
        for _ in range(num_attempts):
            guessed_key = generate_random_key(M)
            try:
                plaintext = aes_ecb_decrypt(guessed_key, captured_ciphertext)
                # Check if first M bytes match the captured r1
                if plaintext[:M] == captured_r1:
                    successes += 1
            except (ValueError, KeyError):
                # Padding error = wrong key, expected
                pass
        elapsed = time.perf_counter() - start_time

        prob = num_attempts / (2 ** (M * 8))
        status = "SECURE" if successes == 0 else "BREACHED"
        print(f"  Keys tested: {num_attempts:,}, valid decryptions: {successes}")
        print(f"  Time: {elapsed:.3f}s, P(success) = {prob:.2e}")
        print(f"  Result: {status}")

        return {
            "attack": "Brute Force Key Guessing",
            "type": "Cryptographic",
            "attempts": num_attempts,
            "successes": successes,
            "time_seconds": round(elapsed, 3),
            "probability": f"{prob:.2e}",
            "status": status,
        }


class VaultKeyRecoveryAttack:
    """Vault key recovery via GF(2) linear algebra.

    Collects XOR equations from challenge-response observations
    and attempts constraint propagation to recover individual keys.
    Tests both with and without vault rotation.
    """

    def _collect_equations(self, vault: SecureVault, num_sessions: int,
                           rotate: bool) -> list:
        """Collect (indices, derived_key) pairs by observing sessions."""
        equations = []
        for _ in range(num_sessions):
            indices = vault.generate_challenge(P)
            derived = vault.derive_key_from_indices(indices)
            equations.append((indices, derived))
            if rotate:
                # Simulate vault update with random session key
                vault.update(generate_random_key(M))
        return equations

    def _try_solve(self, equations: list, actual_keys: list) -> int:
        """Attempt constraint propagation to recover vault keys.

        For each equation with only one unknown index, solve for that key.
        Repeat until no more progress can be made.
        """
        n = len(actual_keys)
        recovered = [None] * n
        known = set()
        remaining = list(equations)

        progress = True
        while progress and len(known) < n:
            progress = False
            next_remaining = []
            for indices, xor_val in remaining:
                unknown = [i for i in indices if i not in known]
                if len(unknown) == 1:
                    # Solve: unknown_key = xor_val XOR all_known_keys
                    idx = unknown[0]
                    known_xor = b'\x00' * M
                    for i in indices:
                        if i != idx and recovered[i] is not None:
                            known_xor = bytes(
                                a ^ b for a, b in zip(known_xor, recovered[i])
                            )
                    recovered[idx] = bytes(
                        a ^ b for a, b in zip(xor_val, known_xor)
                    )
                    known.add(idx)
                    progress = True
                elif len(unknown) > 0:
                    next_remaining.append((indices, xor_val))
            remaining = next_remaining

        correct = sum(
            1 for i in range(n)
            if recovered[i] is not None and recovered[i] == actual_keys[i]
        )
        return correct

    def run(self, num_sessions: int = 50) -> dict:
        print(f"\n  ATTACK 2: Vault Key Recovery (GF(2) Linear Algebra)")
        print(f"  N={N} keys, M={M} bytes, P={P}, sessions={num_sessions}")

        # Without rotation: collect equations from a static vault
        vault_no_rot = SecureVault(N, M)
        vault_no_rot.initialize()
        actual_keys = list(vault_no_rot.keys)  # ground truth
        eq_no_rot = self._collect_equations(vault_no_rot, num_sessions, rotate=False)
        recovered_no_rot = self._try_solve(eq_no_rot, actual_keys)

        # With rotation: vault changes after each session
        vault_rot = SecureVault(N, M)
        vault_rot.initialize()
        actual_keys_rot = list(vault_rot.keys)  # initial ground truth
        eq_rot = self._collect_equations(vault_rot, num_sessions, rotate=True)
        recovered_rot = self._try_solve(eq_rot, actual_keys_rot)

        status = "SECURE" if recovered_rot == 0 else "BREACHED"
        print(f"  Without rotation: {recovered_no_rot}/{N} keys recovered")
        print(f"  With rotation:    {recovered_rot}/{N} keys recovered")
        print(f"  Result: {status}")

        return {
            "attack": "Vault Key Recovery (GF(2))",
            "type": "Cryptographic",
            "no_rotation_recovered": recovered_no_rot,
            "with_rotation_recovered": recovered_rot,
            "total_keys": N,
            "status": status,
        }
