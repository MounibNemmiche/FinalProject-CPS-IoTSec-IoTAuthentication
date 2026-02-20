# ============================================================
# Global Configuration for IoT Secure Vault Authentication
# ============================================================

# --- Secure Vault Parameters ---
N = 16          # Number of keys in the vault
M = 16          # Key size in bytes (16 = AES-128, 32 = AES-256)
P = 6           # Number of keys selected per challenge

# --- Experiment Parameters ---
NUM_DEVICES_LIST = [10, 50, 100, 500, 1000]
NUM_RUNS = 5    # Number of runs to average over

# --- ECC Parameters ---
ECC_CURVE = "P-256"

# --- Simple Password Parameters ---
PASSWORD_LENGTH = 16  # bytes

# --- Attack Simulation Parameters ---
BRUTE_FORCE_ATTEMPTS = 50_000      # Number of random keys to try
VAULT_RECOVERY_SESSIONS = 50       # Number of sessions to observe for GF(2) attack
