# CensorLab Experiments

Reproducible experiments behind the evaluation.  Every number in the paper is
produced by a script in this tree and flows through
`scripts/aggregate_results.py` into `results.tex` (LaTeX macros).

## Layout

```
experiments/
├── common/                 shared harness (all PCAP-mode experiments use it)
│   ├── scenario.sh/.py       loader for the declarative per-scenario scenario.conf
│   ├── harness.sh            uniform per-process measurement (wall, CPU, RSS, baseline)
│   ├── showcase.sh           generic Table 4 runner (warm-up, randomized interleaving)
│   ├── analyze_showcase.py   Table 4 analysis -> table4.{csv,json}
│   ├── report.py             TPR/TNR reporting module (any tool's output vs labels)
│   ├── pcapgen.py            realistic synthetic TCP flows for the scenario PCAPs
│   ├── pcaprecords.py        fast libpcap record / 5-tuple parser (no Scapy)
│   └── baseline.pcap         one-frame PCAP used to measure process startup
├── tools/                  third-party tool configs (suricata/, snort/, opengfw/ incl. nix package)
├── datasets/               real background traffic: fetch_ustc_tfc2016.sh, fetch_iscxvpn2016.sh,
│                           normalize_pcap.py, interleave.py (see "Background datasets")
├── scripts/                run_all.sh, run_all_docker.sh, aggregate_results.py
│
├── 01_http_keyword/        ┐
├── 02_dns_injection/       │ Table 4 / Table 5 scenarios — one directory each, described
├── 03_tls_sni/             │ by scenario.conf (PyCL, CensorLang, Zeek, Scapy, Suricata,
├── 04_shadowsocks/         │ Snort, OpenGFW implementations in comparison/)
├── 05_ml_classification/   ┘
├── 06_model_extraction/    model-extraction attack (live NFQ, Docker)
├── 07_benchmarks/          PCAP-mode throughput/latency vs PCAP size and censor complexity
├── 08_real_traffic/        scenarios interleaved with real background traffic (memory, CPU, variance, startup separation)
├── 09_static_analysis/     CensorLang cost bounds (`censorlab analyze`)
├── 10_nfq_end_to_end/      live NFQ: accuracy, latency, throughput through the censor (Docker)
└── 11_resilience_matrix/   corpus censor programs × real Shadowsocks/obfs4/Snowflake traffic (Docker)
```

### Scenario directory

```
NN_name/
  scenario.conf          declarative description (KEY=value): PCAP, labels, client IP,
                         which tool implementations exist, Table 4 notes
  censor.py/.toml        PyCL program + config
  censor.cl/_lang.toml   CensorLang program + config
  comparison/            zeek_*.zeek, scapy_*.py, suricata_*.rules, snort_*.rules, opengfw_*.yaml
  pcap/                  generate_pcap.py, test.pcap, labels.csv (one label per flow)
  data/                  blocklists, keyword lists
  scripts/run_showcase.sh   -> common/showcase.sh        (Table 4 measurements)
  scripts/analyze.py        -> common/analyze_showcase.py (table4.json, accuracy.json)
  scripts/generate_traffic.py, run_evaluation.sh   live traffic generator (used by 10)
  results/               raw_timings.csv, loc.csv, tools.csv, table4.{csv,json}, accuracy.json,
                         per-tool native outputs and normalized *_decisions.csv
```

## Methodology (PCAP-mode comparisons)

All tools are separate processes measured identically by `common/harness.sh`:
wall-clock, user+sys CPU and peak RSS (GNU time), with one warm-up run, a single
randomized interleaved schedule of all (tool, iteration) pairs, and per-tool
**baseline** runs on a one-frame PCAP that measure process startup/teardown.
`net = wall − startup` is the steady-state analysis cost — this is what
separates Zeek's script compilation and OpenGFW's fixed replay drain from their
analysis time.  The legacy tool-internal timer (`time_us`) is kept for
comparability.  Accuracy is scored by `common/report.py`, which normalizes every
tool's native output (CensorLab decisions, Scapy CSV, Zeek logs, Suricata
eve.json, Snort alert_csv, OpenGFW JSON) to flow ordinals and joins with the
labels; on mixed PCAPs it also counts actions on unlabelled background flows.

The scenario PCAPs contain complete TCP connections (handshake, data, teardown;
`common/pcapgen.py`) so that stateful tools attach their protocol analyzers.

## Prerequisites

```bash
nix develop .#experiments        # censorlab, python3 (+scapy/onnx), zeek, suricata, snort, OpenGFW, GNU time
```

Docker is needed only for 06, 10 and 11.  06 uses the `censorlab-experiments`
image (built from `docker/Dockerfile` by `scripts/run_all_docker.sh`); 10 and 11
use images built by Nix:

```bash
nix build .#docker-live          && docker load < result   # censorlab + iptables + iperf3
nix build .#docker-circumvention && docker load < result   # shadowsocks-rust, lyrebird, snowflake
```

Without Nix, `bash experiments/scripts/run_all_docker.sh` runs the PCAP-mode
pipeline inside a nix-in-docker container.

## Running

```bash
bash experiments/scripts/run_all.sh [ITERATIONS]      # 01-05 showcase, 07 benchmarks, 09 static analysis, aggregation
bash experiments/08_real_traffic/scripts/prepare.sh && bash experiments/08_real_traffic/scripts/run.sh 3   # BACKGROUND=ustc|iscx|combined (default combined)
bash experiments/06_model_extraction/scripts/run_docker.sh   # docker, NUM_PROBES=10000 by default
bash experiments/10_nfq_end_to_end/scripts/run.sh     # docker
bash experiments/11_resilience_matrix/scripts/capture.sh && python3 experiments/11_resilience_matrix/scripts/matrix.py
python3 experiments/scripts/aggregate_results.py --output experiments/results.tex
```

Single scenario: `bash experiments/03_tls_sni/scripts/run_showcase.sh 5 && python3 experiments/03_tls_sni/scripts/analyze.py`.

## Experiments

| # | Experiment | Revision item |
|---|------------|---------------|
| 01 | HTTP keyword filtering (GFW keyword reset) | Table 4/5 |
| 02 | DNS response injection | Table 4/5; Suricata/Snort rows (MR3) |
| 03 | TLS SNI filtering | Table 4/5; Suricata/Snort rows (MR3) |
| 04 | Fully-encrypted-traffic detection (Wu et al. 2023) | Table 4/5; OpenGFW `fet` analyzer (MR1) |
| 05 | ML protocol classification (ONNX) | Table 4/5 |
| — | OpenGFW rulesets for 01–04 | MR1 |
| 06 | Model extraction: 10 000 random (len1, len2) probes against a logistic-regression ONNX censor in Tap mode; fidelity and reconstructed boundary | Fig. 2 |
| 07 | PCAP-mode throughput (1k–50k packets, null/SNI/entropy censors) | MR2 |
| 08 | Real-traffic workloads: scenarios interleaved with USTC-TFC2016 + ISCXVPN2016 (or either alone) at 50/90/97.5 % background; wall ± sd, startup, net, CPU, RSS, TPR/TNR, background collateral | MR4, reviewers B/D |
| 09 | CensorLang static cost bounds per corpus program | reviewers A/E |
| 10 | Live NFQ end-to-end: TPR/TNR, per-connection latency, iperf3 throughput for none/null/PyCL/CensorLang | MR2, reviewer A |
| 11 | Resilience matrix: corpus × real Shadowsocks/obfs4/Snowflake + benign control | reviewer E |

Corpus additions (TLS-in-TLS detector, TSPU TTL normalization using the new
`Rewrite` action, Delay-based throttling) live in `demos/` and are exercised by
the integration tests and by experiment 11.

## Model extraction (06)

1. **Model.** `06_model_extraction/train_model.py` fits a logistic regression
   (the paper's "linear regression") on the first two non-empty payload lengths
   of experiment 05's synthetic `train.pcap` (obfs4-like vs HTTPS) and writes
   `model.onnx` (committed; `float_input` f32[1,2] -> `probabilities`
   [P(obfs4), P(HTTPS)]) and `results/model_params.json`.  Re-train with
   `docker run --rm -v "$PWD/experiments:/censorlab/experiments" censorlab-experiments python3 experiments/06_model_extraction/train_model.py`.
2. **Run.** `scripts/run_docker.sh` (no host sudo) puts a client container,
   which runs CensorLab in Tap/NFQ mode with `censor.py` and sends the probes,
   and a sink container (`probe_server.py`) on one MTU-9000 bridge, so a
   1500-byte probe segment is not split.  Each probe sends two segments of
   random bytes with lengths uniform in 1–1500; the sink never sends
   payload and logs the bytes received per connection.  The outcome is that
   server-side record, cross-checked against whether the client saw the second
   segment ACKed.  The sink has to be on another host: on loopback every packet
   crosses both NFQ hooks, and CensorLab ignores loopback traffic by default
   because it has no direction.
3. **Outputs.** `results/probe_results.csv`, `extraction_stats.json` (blocked
   fraction; fidelity against the ONNX model; a logistic regression fitted only
   on the probe outcomes, compared with the true boundary), and
   `model_extraction.pdf`.  The plot's background is the model's true decision
   regions.

## Background datasets

Experiment 08 interleaves the labelled scenario flows with real captures from
two public datasets.  `BACKGROUND=ustc|iscx|combined` (default `combined`)
selects which; `combined` takes half of each mix's background packets from each
dataset (`datasets/interleave.py`, repeated `--background`).

| Dataset | Content used | Fetch | Location | Size |
|---------|--------------|-------|----------|------|
| **USTC-TFC2016** — W. Wang, M. Zhu, X. Zeng, X. Ye, Y. Sheng, "Malware traffic classification using convolutional neural network for representation learning", ICOIN 2017 | benign half: BitTorrent, Facetime, FTP, Gmail, MySQL, Outlook, Skype, World of Warcraft (SMB/Weibo ship as .7z and are skipped); Ethernet pcap | automatic, `datasets/fetch_ustc_tfc2016.sh` (GitHub copy `davidyslu/USTC-TFC2016`, SHA-256 pinned) | `datasets/ustc-tfc2016/` (git-ignored) | ~140 MB |
| **ISCXVPN2016** — G. Draper-Gil, A. H. Lashkari, M. S. I. Mamun, A. A. Ghorbani, "Characterization of Encrypted and VPN Traffic Using Time-Related Features", ICISSP 2016, pp. 407–414 | non-VPN application captures, one per application (YouTube, Skype audio/video/file/chat, e-mail, Netflix, Facebook chat/audio/video, SFTP, Spotify, Hangouts video/audio/chat, ICQ, FTPS, Vimeo, VoipBuster, AIM, SCP, Gmail chat), each capped at `ISCX_MAX_PACKETS` (20 000) IP frames | **manual download** (registration form), then `datasets/fetch_iscxvpn2016.sh` ingests | `$ISCXVPN2016_DIR` (default `/mnt/shared/jsheffey/censorlab/datasets/iscxvpn2016`), symlinked as `datasets/iscxvpn2016` (git-ignored) | 28 GB captured for the whole dataset per UNB (only the three NonVPN archives are needed: 0.84 + 12.7 + 10.3 GB); ingested `pcap/` is 22 captures, 405 MB (the selector also looks for BitTorrent, which the non-VPN archives do not contain) |

**ISCXVPN2016 manual step.** The Canadian Institute for Cybersecurity (UNB)
serves the dataset only after a registration form (name, e-mail, organisation,
job title, country) at <http://cicresearch.ca/CICDataset/ISCX-VPN-NonVPN-2016/>;
there is no direct, non-interactive URL, and unofficial mirrors are not used.
After submitting the form, "Browse files" → `Dataset/PCAPs/`, download
`NonVPN-PCAPs-01.zip`, `NonVPN-PCAPs-02.zip` and `NonVPN-PCAPs-03.zip` into
`$ISCXVPN2016_DIR/archives/`, then run

```bash
nix develop .#experiments    # provides editcap (wireshark-cli) and unzip
bash experiments/datasets/fetch_iscxvpn2016.sh
```

The script records each archive's SHA-256 on first sight (`archives.sha256`)
and verifies it on every later run; pin the printed sums in the script's
`ARCHIVE_SHA256` table.  Each selected capture is converted from pcapng if
needed (`editcap -F pcap`), re-framed as Ethernet (`normalize_pcap.py`: only
Ethernet, Linux SLL and raw-IP link types are accepted; anything else is
rejected, non-IP frames are dropped) and written to `pcap/NN_<app>.pcap`;
`MANIFEST.tsv` records the source member, original format and link type, frame
counts and SHA-256 of every file, and `SHA256SUMS` is re-verified on each run.

**Licence.** ISCXVPN2016: "publicly available for researchers"; users must
cite Draper-Gil et al. (ICISSP 2016) — the archives are not redistributed
here.  USTC-TFC2016 is published by its authors for research use; cite Wang
et al. (ICOIN 2017).

**Why non-VPN only.** The VPN captures are OpenVPN (UDP) tunnels of the same
applications: one encrypted UDP flow per capture, which adds packets but no
flow or protocol diversity, and would act as a deliberate positive for the
fully-encrypted/ML scenarios rather than as benign background.  They could be
added as a separate background class later; `fetch_iscxvpn2016.sh` never
selects members whose name starts with `vpn`.

## Aggregating results

`python3 experiments/scripts/aggregate_results.py --output experiments/results.tex`
reads every experiment's JSON results and emits `\newcommand` macros:
`\Result<Scenario><Tool>{Time,Loc,WallTime,WallStdev,StartupTime,NetTime,Cpu,Rss,Runs,Status}`,
`\Acc<Scenario><Tool>{TPR,TNR}`, `\ModelExtraction{Probes,BlockedPct,FidelityPct,TrueSlope,ReconSlope,…}`, `\Bench…`, `\Static<Program>…`, `\Real<Scenario><Mix><Tool>…` (Mix suffixed `Iscx`/`Combined` for non-USTC backgrounds).
