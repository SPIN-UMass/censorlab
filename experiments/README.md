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

You can also run the steps separately:

```bash
# Build the image
docker build -f experiments/Dockerfile -t censorlab-experiments .

# Run all experiments
docker run --rm -v $(pwd)/experiments:/censorlab/experiments censorlab-experiments bash experiments/scripts/run_all.sh

# Interactive shell
docker run --rm -it -v $(pwd)/experiments:/censorlab/experiments censorlab-experiments bash

# Single experiment
docker run --rm -v $(pwd)/experiments:/censorlab/experiments censorlab-experiments \
    bash experiments/01_http_keyword/scripts/run_showcase.sh 3
```

The bind mount (`-v`) writes results back to the host so they persist after the container exits.

> **Note:** Experiment 06 (model extraction) requires live NFQ mode and is not supported in Docker showcase mode.

## Experiments

### 01 — HTTP Keyword Filtering

Scans HTTP traffic for GFW-blocked keywords and resets matching connections. Based on real GFW keyword lists.

```bash
# Generate test PCAP (if not present)
python3 experiments/01_http_keyword/pcap/generate_pcap.py

# Run PCAP-mode benchmark (Table 4)
bash experiments/01_http_keyword/scripts/run_showcase.sh [ITERATIONS]

# Run live NFQ evaluation (Table 3) — requires sudo + iptables
bash experiments/01_http_keyword/scripts/run_evaluation.sh

# Analyze results
python3 experiments/01_http_keyword/scripts/analyze.py
```

### 02 — DNS Response Injection

Intercepts DNS queries for forbidden domains and injects forged responses pointing to a sinkhole IP, racing the real resolver.

```bash
python3 experiments/02_dns_injection/pcap/generate_pcap.py
bash experiments/02_dns_injection/scripts/run_showcase.sh [ITERATIONS]
python3 experiments/02_dns_injection/scripts/analyze.py
```

### 03 — TLS SNI Filtering

Extracts the Server Name Indication from TLS ClientHello messages and resets connections to forbidden domains.

```bash
python3 experiments/03_tls_sni/pcap/generate_pcap.py
bash experiments/03_tls_sni/scripts/run_showcase.sh [ITERATIONS]

# Live NFQ evaluation (Table 3)
bash experiments/03_tls_sni/scripts/run_evaluation.sh

python3 experiments/03_tls_sni/scripts/analyze.py
```

### 04 — Shadowsocks / Encrypted Protocol Detection

Applies GFW-style heuristics (Wu et al. 2023) to detect fully encrypted proxy traffic using entropy, popcount, and protocol fingerprint checks.

```bash
python3 experiments/04_shadowsocks/pcap/generate_pcap.py
bash experiments/04_shadowsocks/scripts/run_showcase.sh [ITERATIONS]
python3 experiments/04_shadowsocks/scripts/analyze.py
```

### 05 — ML Protocol Classification

Uses an ONNX neural network to classify encrypted protocols based on packet lengths and directions (Wang et al. 2015). PyCL is the only tool that uses the actual model; others fall back to entropy heuristics.

```bash
python3 experiments/05_ml_classification/pcap/generate_pcap.py

# Train the ONNX model (auto-runs from run_showcase.sh if missing)
python3 experiments/05_ml_classification/train_model.py

bash experiments/05_ml_classification/scripts/run_showcase.sh [ITERATIONS]
python3 experiments/05_ml_classification/scripts/analyze.py
```

### 06 — Model Extraction

Demonstrates that an attacker can reconstruct a censor's ML decision boundary by sending probe traffic and observing block/allow outcomes. Runs in live NFQ mode only.

```bash
bash experiments/06_model_extraction/scripts/run_extraction.sh
python3 experiments/06_model_extraction/scripts/plot_extraction.py
```

### 07 — Throughput & Latency Benchmarks

Measures CensorLab's processing throughput across multiple PCAP sizes and censor complexities (null baseline, SNI filter, entropy checker).

```bash
bash experiments/07_benchmarks/scripts/run_benchmarks.sh [ITERATIONS]
python3 experiments/07_benchmarks/scripts/analyze.py
```

## Aggregating Results

After running experiments, aggregate all results into LaTeX macros for the paper:

```bash
python3 experiments/scripts/aggregate_results.py
```

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
