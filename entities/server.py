import struct
from entities.vault import SecureVault
from entities.crypto_utils import (
    generate_random_key,
    aes_ecb_encrypt,
    aes_ecb_decrypt,
    xor_bytes,
)
from config import M, P


class IoTServer:
    """
    IoT Server implementing the Secure Vault authentication protocol.
    Executes Steps 2 and 4 of the handshake.
    """

    def __init__(self):
        self.registered_devices: dict[str, SecureVault] = {}
        # Transient session state per device
        self._sessions: dict[str, dict] = {}

    def register_device(self, device_id: str, vault: SecureVault) -> None:
        """Register a device with its shared vault."""
        self.registered_devices[device_id] = vault

    def step2_challenge(self, m1: dict) -> dict:
        """
        Step 2: Server -> Client
        Receives M1 = {device_id, session_id}.
        Validates device, generates challenge C1 and nonce r1.
        Returns M2 = {C1, r1}
        """
        device_id = m1["device_id"]

        if device_id not in self.registered_devices:
            raise ValueError(f"Unknown device: {device_id}")

        vault = self.registered_devices[device_id]

        # Generate challenge and nonce
        c1 = vault.generate_challenge(P)
        r1 = generate_random_key(M)

        # Store session state
        self._sessions[device_id] = {
            "session_id": m1["session_id"],
            "C1": c1,
            "r1": r1,
        }

        return {"C1": c1, "r1": r1}

    def step4_verify_and_respond(self, device_id: str, m3: dict) -> dict:
        """
        Step 4: Server -> Client
        Receives M3 = {ciphertext} from device.
        Decrypts, validates r1, generates response.
        Returns M4 = {ciphertext}
        Also stores the computed session_key on the session.
        Raises ValueError if authentication fails.
        """
        session = self._sessions[device_id]
        vault = self.registered_devices[device_id]

        # Derive k1 from C1
        k1 = vault.derive_key_from_indices(session["C1"])

        # Decrypt M3
        plaintext = aes_ecb_decrypt(k1, m3["ciphertext"])

        # Extract fields: r1 (M) || t1 (M) || len_c2 (1) || C2 (len_c2) || r2 (M)
        offset = 0
        r1_received = plaintext[offset : offset + M]
        offset += M
        t1 = plaintext[offset : offset + M]
        offset += M
        len_c2 = plaintext[offset]
        offset += 1
        c2 = list(struct.unpack(f"{len_c2}B", plaintext[offset : offset + len_c2]))
        offset += len_c2
        r2 = plaintext[offset : offset + M]

        # Validate r1
        if r1_received != session["r1"]:
            raise ValueError("Authentication failed: r1 mismatch (device not authenticated)")

        # Derive k2 from C2
        k2 = vault.derive_key_from_indices(c2)

        # Generate partial session key t2
        t2 = generate_random_key(M)

        # Construct and encrypt response payload: r2 || t2
        payload = r2 + t2

        ciphertext = aes_ecb_encrypt(k2, payload)

        # Compute session key and update vault
        session_key = xor_bytes(t1, t2)
        vault.update(session_key)

        # Store session key for reference
        session["session_key"] = session_key

        return {"ciphertext": ciphertext}

    def get_session_key(self, device_id: str) -> bytes:
        """Retrieve the session key from the last completed authentication."""
        return self._sessions[device_id]["session_key"]
