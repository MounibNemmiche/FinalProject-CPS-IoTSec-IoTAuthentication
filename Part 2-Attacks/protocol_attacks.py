"""
Protocol-level attacks against the Secure Vault authentication system.

Adapted from Alessandro's implementation to use the project's
existing entities/ module (no duplicate protocol code).

Attack 3 - Replay Attack:
    Captures M1 and M3 from a legitimate session, then replays
    them after the vault has been updated.

Attack 4 - Man-in-the-Middle (MITM):
    Three strategies: challenge modification, message forgery,
    and bit-flipping on the ciphertext.
"""

import struct

from config import N, M, P
from entities.vault import SecureVault
from entities.device import IoTDevice
from entities.server import IoTServer
from entities.crypto_utils import generate_random_key, aes_ecb_encrypt


def _setup_pair():
    """Create a fresh device-server pair with synchronized vaults."""
    vault = SecureVault(N, M)
    vault.initialize()
    device = IoTDevice("replay_target", vault.clone())
    server = IoTServer()
    server.register_device("replay_target", vault.clone())
    return device, server


class ReplayAttack:
    """Replay captured messages from a previous session."""

    def run(self) -> dict:
        print(f"\n  ATTACK 3: Replay Attack")
        print(f"  N={N}, M={M} bytes, P={P}")

        device, server = _setup_pair()

        # --- Legitimate session (attacker eavesdrops) ---
        m1 = device.step1_initiate()
        m2 = server.step2_challenge(m1)
        m3 = device.step3_respond(m2)
        m4 = server.step4_verify_and_respond("replay_target", m3)
        session_key = device.step5_finalize(m4)

        # Capture messages before vault update
        captured_m1 = dict(m1)
        captured_m3 = dict(m3)
        print(f"  Captured M1 (device_id={captured_m1['device_id']}) and M3")
        print(f"  Vault has been updated after successful session")

        # --- Replay attempt (vault has already rotated) ---
        # Attacker replays the old M1 to get a new M2
        new_m2 = server.step2_challenge(captured_m1)

        # Attacker replays the old M3 (encrypted with old k1)
        # Server will try to decrypt with new k1 (derived from new vault)
        attack_failed = True
        try:
            server.step4_verify_and_respond("replay_target", captured_m3)
            attack_failed = False  # Should NOT reach here
        except (ValueError, Exception):
            attack_failed = True  # Expected: decryption or r1 mismatch

        status = "SECURE" if attack_failed else "BREACHED"
        print(f"  Replayed old M3 to new session: server {'REJECTED' if attack_failed else 'ACCEPTED'}")
        print(f"  Result: {status}")

        return {
            "attack": "Replay Attack",
            "type": "Protocol",
            "server_rejected": attack_failed,
            "status": status,
        }


class MITMAttack:
    """Man-in-the-Middle with three strategies."""

    def run(self) -> dict:
        print(f"\n  ATTACK 4: Man-in-the-Middle (MITM)")
        print(f"  N={N}, M={M} bytes, P={P}")

        results = []

        # ---- Strategy A: Modify r1 in M2 ----
        device_a, server_a = _setup_pair()
        m1_a = device_a.step1_initiate()
        m2_a = server_a.step2_challenge(m1_a)

        # MITM tampers with r1
        tampered_m2 = {"C1": m2_a["C1"], "r1": generate_random_key(M)}
        m3_a = device_a.step3_respond(tampered_m2)

        # Server tries to verify -- r1 in M3 won't match server's r1
        blocked_a = True
        try:
            server_a.step4_verify_and_respond("replay_target", m3_a)
            blocked_a = False
        except (ValueError, Exception):
            blocked_a = True
        results.append(blocked_a)
        print(f"  Strategy A (modify r1):    {'BLOCKED' if blocked_a else 'PASSED'}")

        # ---- Strategy B: Forge M3 with a random key ----
        device_b, server_b = _setup_pair()
        m1_b = device_b.step1_initiate()
        m2_b = server_b.step2_challenge(m1_b)

        # MITM forges M3 using a random encryption key
        fake_key = generate_random_key(M)
        c2_indices = list(range(P))
        c2_encoded = struct.pack(f"B{len(c2_indices)}B", len(c2_indices), *c2_indices)
        forged_payload = m2_b["r1"] + generate_random_key(M) + c2_encoded + generate_random_key(M)
        forged_m3 = {"ciphertext": aes_ecb_encrypt(fake_key, forged_payload)}

        blocked_b = True
        try:
            server_b.step4_verify_and_respond("replay_target", forged_m3)
            blocked_b = False
        except (ValueError, Exception):
            blocked_b = True
        results.append(blocked_b)
        print(f"  Strategy B (forged M3):    {'BLOCKED' if blocked_b else 'PASSED'}")

        # ---- Strategy C: Bit-flipping on M3 ciphertext ----
        device_c, server_c = _setup_pair()
        m1_c = device_c.step1_initiate()
        m2_c = server_c.step2_challenge(m1_c)
        m3_c = device_c.step3_respond(m2_c)

        # MITM flips a bit in the ciphertext
        ct = bytearray(m3_c["ciphertext"])
        ct[len(ct) // 2] ^= 0x01  # flip one bit in the middle
        flipped_m3 = {"ciphertext": bytes(ct)}

        blocked_c = True
        try:
            server_c.step4_verify_and_respond("replay_target", flipped_m3)
            blocked_c = False
        except (ValueError, Exception):
            blocked_c = True
        results.append(blocked_c)
        print(f"  Strategy C (bit-flipping): {'BLOCKED' if blocked_c else 'PASSED'}")

        all_blocked = all(results)
        status = "SECURE" if all_blocked else "BREACHED"
        print(f"  Result: {status}")

        return {
            "attack": "Man-in-the-Middle (MITM)",
            "type": "Protocol",
            "strategy_a_blocked": results[0],
            "strategy_b_blocked": results[1],
            "strategy_c_blocked": results[2],
            "status": status,
        }
