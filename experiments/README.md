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
├── datasets/               real background traffic: fetch_ustc_tfc2016.sh, interleave.py
├── scripts/                run_all.sh, run_all_docker.sh, aggregate_results.py
│
├── 01_http_keyword/        ┐
├── 02_dns_injection/       │ Table 4 / Table 5 scenarios — one directory each, described
├── 03_tls_sni/             │ by scenario.conf (PyCL, CensorLang, Zeek, Scapy, Suricata,
├── 04_shadowsocks/         │ Snort, OpenGFW implementations in comparison/)
├── 05_ml_classification/   ┘
├── 06_model_extraction/    model-extraction attack (live NFQ)
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

Docker is needed only for 10 and 11 (images are built by Nix, no Dockerfile):

```bash
nix build .#docker-live          && docker load < result   # censorlab + iptables + iperf3
nix build .#docker-circumvention && docker load < result   # shadowsocks-rust, lyrebird, snowflake
```

Without Nix, `bash experiments/scripts/run_all_docker.sh` runs the PCAP-mode
pipeline inside a nix-in-docker container.

## Running

```bash
bash experiments/scripts/run_all.sh [ITERATIONS]      # 01-05 showcase, 07 benchmarks, 09 static analysis, aggregation
bash experiments/08_real_traffic/scripts/prepare.sh && bash experiments/08_real_traffic/scripts/run.sh 3
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
| 06 | Model extraction against a censor's classifier | Fig. 2 |
| 07 | PCAP-mode throughput (1k–50k packets, null/SNI/entropy censors) | MR2 |
| 08 | Real-traffic workloads: scenarios interleaved with USTC-TFC2016 at 50/90/97.5 % background; wall ± sd, startup, net, CPU, RSS, TPR/TNR, background collateral | MR4, reviewers B/D |
| 09 | CensorLang static cost bounds per corpus program | reviewers A/E |
| 10 | Live NFQ end-to-end: TPR/TNR, per-connection latency, iperf3 throughput for none/null/PyCL/CensorLang | MR2, reviewer A |
| 11 | Resilience matrix: corpus × real Shadowsocks/obfs4/Snowflake + benign control | reviewer E |

Corpus additions (TLS-in-TLS detector, TSPU TTL normalization using the new
`Rewrite` action, Delay-based throttling) live in `demos/` and are exercised by
the integration tests and by experiment 11.

## Aggregating results

`python3 experiments/scripts/aggregate_results.py --output experiments/results.tex`
reads every experiment's JSON results and emits `\newcommand` macros:
`\Result<Scenario><Tool>{Time,Loc,WallTime,WallStdev,StartupTime,NetTime,Cpu,Rss,Runs,Status}`,
`\Acc<Scenario><Tool>{TPR,TNR}`, `\Bench…`, `\Static<Program>…`, `\Real<Scenario><Mix><Tool>…`.
