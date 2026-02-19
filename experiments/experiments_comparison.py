import os
import time
import statistics
from prettytable import PrettyTable
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

from config import N, M, P, NUM_DEVICES_LIST, NUM_RUNS, PASSWORD_LENGTH
from entities.vault import SecureVault
from entities.device import IoTDevice
from entities.server import IoTServer
from entities.crypto_utils import generate_random_key, compute_hmac


# ============================================================
# Authentication Method 1: Secure Vault (SV)
# ============================================================

def run_sv_single_auth(device: IoTDevice, server: IoTServer) -> dict:
    """Run a single SV authentication and return timing breakdown (in seconds)."""
    timings = {}

    # Step 1: Device initiates
    t0 = time.perf_counter()
    m1 = device.step1_initiate()
    timings["step1"] = time.perf_counter() - t0

    # Step 2: Server challenges
    t0 = time.perf_counter()
    m2 = server.step2_challenge(m1)
    timings["step2"] = time.perf_counter() - t0

    # Step 3: Device responds
    t0 = time.perf_counter()
    m3 = device.step3_respond(m2)
    timings["step3"] = time.perf_counter() - t0

    # Step 4: Server verifies and responds
    t0 = time.perf_counter()
    m4 = server.step4_verify_and_respond(device.device_id, m3)
    timings["step4"] = time.perf_counter() - t0

    # Step 5: Device finalizes
    t0 = time.perf_counter()
    session_key = device.step5_finalize(m4)
    timings["step5"] = time.perf_counter() - t0

    timings["total"] = sum(timings.values())
    return timings


def run_sv_experiment(num_devices: int) -> list[float]:
    """Run SV authentication for num_devices and return list of per-device total times (ms)."""
    server = IoTServer()
    device_times = []

    for i in range(num_devices):
        vault = SecureVault(N, M)
        vault.initialize()
        device_id = f"device_{i:04d}"
        device = IoTDevice(device_id, vault.clone())
        server.register_device(device_id, vault.clone())

        timings = run_sv_single_auth(device, server)
        device_times.append(timings["total"] * 1000)  # convert to ms

    return device_times


# ============================================================
# Authentication Method 2: ECC (ECDSA-based mutual auth)
# ============================================================

def run_ecc_single_auth(device_key, device_pub, server_key, server_pub) -> dict:
    """
    Run a single ECC mutual authentication and return timing breakdown.
    Protocol:
      1. Device sends nonce_d signed with device private key
      2. Server verifies signature, sends nonce_s signed with server private key
      3. Device verifies server signature
    """
    timings = {}

    # Step 1: Device generates nonce and signs it
    t0 = time.perf_counter()
    nonce_d = generate_random_key(16)
    h_d = SHA256.new(nonce_d)
    signer_d = DSS.new(device_key, "fips-186-3")
    sig_d = signer_d.sign(h_d)
    timings["device_sign"] = time.perf_counter() - t0

    # Step 2: Server verifies device signature
    t0 = time.perf_counter()
    h_d_verify = SHA256.new(nonce_d)
    verifier_d = DSS.new(device_pub, "fips-186-3")
    verifier_d.verify(h_d_verify, sig_d)
    timings["server_verify_device"] = time.perf_counter() - t0

    # Step 3: Server generates nonce and signs it
    t0 = time.perf_counter()
    nonce_s = generate_random_key(16)
    h_s = SHA256.new(nonce_s)
    signer_s = DSS.new(server_key, "fips-186-3")
    sig_s = signer_s.sign(h_s)
    timings["server_sign"] = time.perf_counter() - t0

    # Step 4: Device verifies server signature
    t0 = time.perf_counter()
    h_s_verify = SHA256.new(nonce_s)
    verifier_s = DSS.new(server_pub, "fips-186-3")
    verifier_s.verify(h_s_verify, sig_s)
    timings["device_verify_server"] = time.perf_counter() - t0

    timings["total"] = sum(timings.values())
    return timings


def run_ecc_experiment(num_devices: int) -> list[float]:
    """Run ECC authentication for num_devices and return list of per-device total times (ms)."""
    # Server key pair (generated once)
    server_key = ECC.generate(curve="P-256")
    server_pub = server_key.public_key()

    device_times = []
    for i in range(num_devices):
        # Each device has its own key pair
        t_keygen = time.perf_counter()
        device_key = ECC.generate(curve="P-256")
        device_pub = device_key.public_key()
        keygen_time = time.perf_counter() - t_keygen

        timings = run_ecc_single_auth(device_key, device_pub, server_key, server_pub)
        total_with_keygen = (keygen_time + timings["total"]) * 1000
        device_times.append(total_with_keygen)

    return device_times


# ============================================================
# Authentication Method 3: Simple/Rotating Password
# ============================================================

def run_password_single_auth(password: bytes) -> dict:
    """
    Run a single password-based challenge-response authentication.
    Protocol:
      1. Server sends random nonce
      2. Device computes SHA256(password || nonce) and sends response
      3. Server verifies by computing the same hash
    """
    timings = {}

    # Step 1: Server generates nonce
    t0 = time.perf_counter()
    nonce = generate_random_key(16)
    timings["server_challenge"] = time.perf_counter() - t0

    # Step 2: Device computes response
    t0 = time.perf_counter()
    h_device = SHA256.new(password + nonce).digest()
    timings["device_respond"] = time.perf_counter() - t0

    # Step 3: Server verifies
    t0 = time.perf_counter()
    h_server = SHA256.new(password + nonce).digest()
    assert h_device == h_server
    timings["server_verify"] = time.perf_counter() - t0

    timings["total"] = sum(timings.values())
    return timings


def run_password_experiment(num_devices: int) -> list[float]:
    """Run password auth for num_devices and return list of per-device total times (ms)."""
    device_times = []
    for i in range(num_devices):
        password = generate_random_key(PASSWORD_LENGTH)
        timings = run_password_single_auth(password)
        device_times.append(timings["total"] * 1000)
    return device_times


# ============================================================
# Experiment Runner
# ============================================================

def run_all_experiments() -> dict:
    """
    Run all three authentication methods across different device counts.
    Returns structured results dict.
    """
    methods = {
        "Secure Vault": run_sv_experiment,
        "ECC (P-256)": run_ecc_experiment,
        "Simple Password": run_password_experiment,
    }

    results = {}
    for method_name, method_fn in methods.items():
        results[method_name] = {}
        for num_devices in NUM_DEVICES_LIST:
            run_avgs = []
            for run in range(NUM_RUNS):
                times = method_fn(num_devices)
                avg_time = statistics.mean(times)
                run_avgs.append(avg_time)
            results[method_name][num_devices] = {
                "mean": statistics.mean(run_avgs),
                "stdev": statistics.stdev(run_avgs) if len(run_avgs) > 1 else 0.0,
                "min": min(run_avgs),
                "max": max(run_avgs),
            }
            print(f"  {method_name} | {num_devices} devices: "
                  f"{results[method_name][num_devices]['mean']:.4f} ms (avg)")
    return results


def display_results_table(results: dict) -> None:
    """Display results as a formatted PrettyTable."""
    table = PrettyTable()
    table.field_names = ["# Devices"] + list(results.keys())
    table.float_format = ".4"

    for num_devices in NUM_DEVICES_LIST:
        row = [num_devices]
        for method_name in results:
            stats = results[method_name][num_devices]
            row.append(f"{stats['mean']:.4f} +/- {stats['stdev']:.4f}")
        table.add_row(row)

    print("\n=== Authentication Time Comparison (ms per device) ===")
    print(table)

    # Detailed breakdown table
    detail_table = PrettyTable()
    detail_table.field_names = ["# Devices", "Method", "Mean (ms)", "Std Dev", "Min (ms)", "Max (ms)"]
    detail_table.float_format = ".4"

    for num_devices in NUM_DEVICES_LIST:
        for method_name in results:
            stats = results[method_name][num_devices]
            detail_table.add_row([
                num_devices, method_name,
                f"{stats['mean']:.4f}", f"{stats['stdev']:.4f}",
                f"{stats['min']:.4f}", f"{stats['max']:.4f}",
            ])

    print("\n=== Detailed Breakdown ===")
    print(detail_table)


def plot_results(results: dict, output_dir: str = None) -> None:
    """Generate bar chart and line chart comparing authentication methods."""
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(__file__), "..", "results")
    os.makedirs(output_dir, exist_ok=True)

    methods = list(results.keys())
    colors = ["#2196F3", "#F44336", "#4CAF50"]

    # --- Bar Chart (like Figure 3 in the paper) ---
    fig, ax = plt.subplots(figsize=(12, 6))
    x_positions = range(len(NUM_DEVICES_LIST))
    bar_width = 0.25

    for idx, method in enumerate(methods):
        means = [results[method][nd]["mean"] for nd in NUM_DEVICES_LIST]
        stdevs = [results[method][nd]["stdev"] for nd in NUM_DEVICES_LIST]
        offset = (idx - 1) * bar_width
        bars = ax.bar(
            [x + offset for x in x_positions],
            means,
            bar_width,
            yerr=stdevs,
            label=method,
            color=colors[idx],
            capsize=3,
        )

    ax.set_xlabel("Number of Devices")
    ax.set_ylabel("Average Authentication Time (ms)")
    ax.set_title("Authentication Time Comparison: SV vs ECC vs Simple Password")
    ax.set_xticks(x_positions)
    ax.set_xticklabels(NUM_DEVICES_LIST)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "bar_chart_comparison.png"), dpi=150)
    plt.close()
    print(f"\nBar chart saved to {os.path.join(output_dir, 'bar_chart_comparison.png')}")

    # --- Line Chart ---
    fig, ax = plt.subplots(figsize=(10, 6))

    for idx, method in enumerate(methods):
        means = [results[method][nd]["mean"] for nd in NUM_DEVICES_LIST]
        ax.plot(NUM_DEVICES_LIST, means, marker="o", label=method, color=colors[idx], linewidth=2)

    ax.set_xlabel("Number of Devices")
    ax.set_ylabel("Average Authentication Time (ms)")
    ax.set_title("Authentication Time vs Number of Devices")
    ax.legend()
    ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "line_chart_scaling.png"), dpi=150)
    plt.close()
    print(f"Line chart saved to {os.path.join(output_dir, 'line_chart_scaling.png')}")

    # --- Log-scale Bar Chart (useful when ECC >> SV) ---
    fig, ax = plt.subplots(figsize=(12, 6))

    for idx, method in enumerate(methods):
        means = [results[method][nd]["mean"] for nd in NUM_DEVICES_LIST]
        offset = (idx - 1) * bar_width
        ax.bar(
            [x + offset for x in x_positions],
            means,
            bar_width,
            label=method,
            color=colors[idx],
        )

    ax.set_xlabel("Number of Devices")
    ax.set_ylabel("Average Authentication Time (ms) [log scale]")
    ax.set_title("Authentication Time Comparison (Log Scale)")
    ax.set_xticks(x_positions)
    ax.set_xticklabels(NUM_DEVICES_LIST)
    ax.set_yscale("log")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "bar_chart_log_scale.png"), dpi=150)
    plt.close()
    print(f"Log-scale bar chart saved to {os.path.join(output_dir, 'bar_chart_log_scale.png')}")
