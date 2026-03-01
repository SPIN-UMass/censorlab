# CensorLab Experiments

Reproducible experiments for evaluation. Each experiment implements a censorship scenario using four tools — **PyCL** (Python), **CensorLang** (DSL), **Zeek**, and **Scapy** — and benchmarks them for timing (Table 4) and optionally accuracy (Table 3).

## Prerequisites

Enter the Nix experiments shell (provides CensorLab, Python with dependencies, Zeek, etc.):

```bash
nix develop .#experiments
```

### Docker Mode (no Nix required)

For users without Nix, a single script builds the Docker image and runs every experiment:

```bash
bash experiments/scripts/run_all_docker.sh [ITERATIONS]
```

This builds a nix-in-docker image, then runs the full PCAP-mode pipeline inside the container. Results are written back to the host via a bind mount.

## Experiments

### 01 — HTTP Keyword Filtering

Scans HTTP traffic for GFW-blocked keywords and resets matching connections. Based on real GFW keyword lists.

### 02 — DNS Response Injection

Intercepts DNS queries for forbidden domains and injects forged responses pointing to a sinkhole IP, racing the real resolver.

### 03 — TLS SNI Filtering

Extracts the Server Name Indication from TLS ClientHello messages and resets connections to forbidden domains.

### 04 — Shadowsocks / Encrypted Protocol Detection

Applies GFW-style heuristics (Wu et al. 2023) to detect fully encrypted proxy traffic using entropy, popcount, and protocol fingerprint checks.

### 05 — ML Protocol Classification

Uses an ONNX neural network to classify encrypted protocols based on packet lengths and directions (Wang et al. 2015). PyCL is the only tool that uses the actual model; others fall back to entropy heuristics.

### 06 — Model Extraction

Demonstrates that an attacker can reconstruct a censor's ML decision boundary by sending probe traffic and observing block/allow outcomes. Runs in live NFQ mode only.

### 07 — Throughput & Latency Benchmarks

Measures CensorLab's processing throughput across multiple PCAP sizes and censor complexities (null baseline, SNI filter, entropy checker).

## Aggregating Results

After running experiments, aggregate all results into LaTeX macros for the paper:

This reads `table3.json` and `table4.json` from each experiment's `results/` directory and writes `results.tex`.

## Directory Structure

Each experiment follows a standard layout:

```
XX_name/
  censor.py              # PyCL censor script
  censor.toml            # CensorLab config (Python mode)
  censor.cl              # CensorLang DSL script
  censor_lang.toml       # CensorLab config (CensorLang mode)
  comparison/            # Zeek and Scapy implementations
  pcap/                  # Test PCAPs + generation scripts
    generate_pcap.py
    test.pcap
    labels.csv           # Ground truth labels
  scripts/               # Run and analysis scripts
    run_showcase.sh      # PCAP-mode benchmark (Table 4)
    run_evaluation.sh    # Live NFQ evaluation (Table 3, where applicable)
    analyze.py           # Post-processing, generates table3.json / table4.json
  results/               # Output CSV/JSON files
  data/                  # Blocklists, keyword lists, etc.
```
