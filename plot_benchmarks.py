"""
Produces the three comparison charts for the thesis:

  1. prover_comparison.png   — prover time (ms) : DL vs EC vs Bulletproofs
  2. verifier_comparison.png — verifier time (ms) : DL vs EC vs Bulletproofs
  3. proof_size_comparison.png — proof size (bytes) : DL vs EC vs Bulletproofs

Timing data comes from JMH JSON files (one per implementation).
Proof-size data comes from proof-sizes.json (produced by
ProofSizeMeasurement.java).

Usage:
    python plot_benchmarks.py dl.json ec.json bp.json \
        --labels "DL bit-decomp" "EC bit-decomp" "Bulletproofs" \
        --sizes proof-sizes.json -o charts
"""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np

# One distinct colour per implementation (index-aligned with the inputs)
IMPL_COLORS = ["#c0392b", "#1a6faf", "#27ae60", "#e67e22", "#8e44ad"]

X_AXIS_LABEL = "Range size (bits)"


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def short_name(full_name: str) -> str:
    return full_name.rsplit(".", 1)[-1]


def parse_timing(path: str):
    """Reads a JMH JSON file into per-metric {bit: value} maps.

    Metrics:
      prover     — prover_normal       avg time (ms/op, lower better)
      verifier   — verifier_valid      avg time (ms/op, lower better)
      tampered   — verifier_tampered   avg time (ms/op, lower better)
      throughput — prover_throughput   ops/s     (higher better)
    """
    with open(path) as f:
        entries = json.load(f)

    acc = {k: defaultdict(list) for k in ("prover", "verifier", "tampered", "throughput")}

    for entry in entries:
        params = entry.get("params") or {}
        if "bitLength" not in params:
            continue
        bit   = int(params["bitLength"])
        name  = short_name(entry["benchmark"])
        mode  = entry.get("mode")
        unit  = entry["primaryMetric"].get("scoreUnit")
        score = entry["primaryMetric"]["score"]

        if mode == "avgt" and unit == "ms/op":
            if name == "prover_normal":
                acc["prover"][bit].append(score)
            elif name == "verifier_valid":
                acc["verifier"][bit].append(score)
            elif name == "verifier_tampered":
                acc["tampered"][bit].append(score)
        elif mode == "thrpt" and name == "prover_throughput":
            acc["throughput"][bit].append(score)

    bits = sorted({b for m in acc.values() for b in m})
    return {
        "bits":       bits,
        "prover":     {b: float(np.mean(v)) for b, v in acc["prover"].items()},
        "verifier":   {b: float(np.mean(v)) for b, v in acc["verifier"].items()},
        "tampered":   {b: float(np.mean(v)) for b, v in acc["tampered"].items()},
        "throughput": {b: float(np.mean(v)) for b, v in acc["throughput"].items()},
    }


def fmt_bytes(n: float) -> str:
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{int(n)} B"


def fmt_num(v: float) -> str:
    """Adaptive number formatting so sub-millisecond values stay readable.

    Sub-thousandth values use proper scientific notation a*10^b rendered
    through matplotlib mathtext (e.g. 5.0x10^-4) rather than the
    programming-style "5.0e-04" form, which is the academic standard.
    """
    if v >= 100:
        return f"{v:.0f}"
    if v >= 1:
        return f"{v:.1f}"
    if v >= 0.001:
        return f"{v:.4f}"
    exp = int(np.floor(np.log10(v)))
    mant = v / 10 ** exp
    return rf"${mant:.1f}\times10^{{{exp}}}$"


# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------

def chart_metric(runs, labels, key, title, ylabel, out_path, value_fmt=fmt_num):
    """Generic grouped bar chart (log scale) for one timing metric.

    Only bit-lengths present in EVERY implementation are shown (drops e.g.
    64-bit, which Bulletproofs cannot produce) so the comparison stays fair.
    """
    bit_sets = [set(run[key]) for run in runs if run.get(key)]
    all_bits = sorted(set.intersection(*bit_sets)) if bit_sets else []
    if not all_bits:
        print(f"No shared '{key}' data found; skipping {out_path}")
        return

    x = np.arange(len(all_bits))
    width = 0.8 / max(len(runs), 1)

    fig, ax = plt.subplots(figsize=(11, 6))
    for i, (run, label) in enumerate(zip(runs, labels)):
        values = [run[key].get(b, 0) for b in all_bits]
        offset = (i - (len(runs) - 1) / 2) * width
        bars = ax.bar(x + offset, values, width,
                      color=IMPL_COLORS[i % len(IMPL_COLORS)],
                      label=label, edgecolor="white", zorder=3)
        for bar, b, v in zip(bars, all_bits, values):
            if v <= 0:
                continue
            ax.annotate(value_fmt(v),
                        xy=(bar.get_x() + bar.get_width() / 2, v),
                        xytext=(0, 3), textcoords="offset points",
                        ha="center", va="bottom",
                        fontsize=8, fontweight="bold",
                        color=IMPL_COLORS[i % len(IMPL_COLORS)])

    ax.set_yscale("log")
    ax.set_title(title, fontsize=14, fontweight="bold", pad=12)
    ax.set_xlabel(X_AXIS_LABEL, fontsize=12)
    ax.set_ylabel(ylabel, fontsize=12)
    ax.set_xticks(x)
    ax.set_xticklabels([str(b) for b in all_bits], fontsize=11)
    ax.grid(True, axis="y", which="both", linestyle="--", alpha=0.4, zorder=0)
    ax.legend(fontsize=11)

    fig.tight_layout()
    fig.savefig(out_path, dpi=200)
    plt.close(fig)
    print(f"Saved: {out_path}")


def chart_proof_size(sizes_path, out_path):
    """Grouped bar chart (log scale) of proof size in bytes across impls."""
    with open(sizes_path) as f:
        data = json.load(f)  # {"DL...": {"4": 9736, ...}, ...}

    impls    = list(data.keys())
    # Only bit-lengths present in EVERY implementation, keeping the bars fair.
    bit_sets = [set(int(b) for b in impl) for impl in data.values() if impl]
    all_bits = sorted(set.intersection(*bit_sets)) if bit_sets else []
    if not all_bits:
        print(f"No shared proof-size data in {sizes_path}; skipping {out_path}")
        return

    x = np.arange(len(all_bits))
    width = 0.8 / max(len(impls), 1)

    fig, ax = plt.subplots(figsize=(11, 6))
    for i, impl in enumerate(impls):
        values = [data[impl].get(str(b), 0) for b in all_bits]
        offset = (i - (len(impls) - 1) / 2) * width
        bars = ax.bar(x + offset, values, width,
                      color=IMPL_COLORS[i % len(IMPL_COLORS)],
                      label=impl, edgecolor="white", zorder=3)
        for bar, b, v in zip(bars, all_bits, values):
            if v <= 0:
                continue
            ax.annotate(fmt_bytes(v),
                        xy=(bar.get_x() + bar.get_width() / 2, v),
                        xytext=(0, 3), textcoords="offset points",
                        ha="center", va="bottom",
                        fontsize=8, fontweight="bold",
                        color=IMPL_COLORS[i % len(IMPL_COLORS)])

    ax.set_yscale("log")
    ax.set_title("Proof Size — DL vs EC vs Bulletproofs",
                 fontsize=14, fontweight="bold", pad=12)
    ax.set_xlabel(X_AXIS_LABEL, fontsize=12)
    ax.set_ylabel("Proof size (bytes, log scale)", fontsize=12)
    ax.set_xticks(x)
    ax.set_xticklabels([str(b) for b in all_bits], fontsize=11)
    ax.grid(True, axis="y", which="both", linestyle="--", alpha=0.4, zorder=0)
    ax.legend(fontsize=11)

    fig.tight_layout()
    fig.savefig(out_path, dpi=200)
    plt.close(fig)
    print(f"Saved: {out_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("files", nargs="*",
                        help="Timing JMH JSON files (one per implementation)")
    parser.add_argument("--labels", nargs="*",
                        help="Display labels (one per timing file)")
    parser.add_argument("--sizes",
                        help="proof-sizes.json for the proof-size chart")
    parser.add_argument("-o", "--out", default=".", help="Output directory")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)

    # --- Timing charts ---
    runs, used = [], []
    for path in args.files:
        if not os.path.exists(path):
            print(f"Skipping missing file: {path}")
            continue
        runs.append(parse_timing(path))
        used.append(path)

    if runs:
        labels = args.labels or [os.path.splitext(os.path.basename(p))[0] for p in used]
        if len(labels) < len(runs):
            labels += [f"run{i}" for i in range(len(labels), len(runs))]
        chart_metric(runs, labels, "prover",
                     "Prover Time — DL vs EC vs Bulletproofs",
                     "Prover time (ms / operation, log scale)",
                     os.path.join(args.out, "prover_comparison.png"))
        chart_metric(runs, labels, "verifier",
                     "Verifier Time (valid proof) — DL vs EC vs Bulletproofs",
                     "Verifier time (ms / operation, log scale)",
                     os.path.join(args.out, "verifier_comparison.png"))
        chart_metric(runs, labels, "tampered",
                     "Invalid-Proof Verifier Time — DL vs EC vs Bulletproofs",
                     "Verifier time on a tampered proof (ms / op, log scale)",
                     os.path.join(args.out, "tampered_comparison.png"))
        chart_metric(runs, labels, "throughput",
                     "Prover Throughput — DL vs EC vs Bulletproofs",
                     "Throughput (proofs / second, log scale)",
                     os.path.join(args.out, "throughput_comparison.png"))

    # --- Proof size chart ---
    if args.sizes:
        if os.path.exists(args.sizes):
            chart_proof_size(args.sizes,
                             os.path.join(args.out, "proof_size_comparison.png"))
        else:
            print(f"Skipping missing sizes file: {args.sizes}")

    if not runs and not args.sizes:
        print("Nothing to plot. Provide timing JSON files and/or --sizes.")


if __name__ == "__main__":
    main()
