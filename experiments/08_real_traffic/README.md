# 08 — Real-traffic workloads with background mixes

Addresses meta-review item **MR4** (and reviewers B/D): the Table 4 microbenchmarks
use small synthetic PCAPs that contain nothing but the labelled flows, and
measured Zeek's process startup as analysis time.  This experiment re-runs every
tool from Table 4 on the same labelled scenario flows *interleaved with real
traffic* (the benign half of USTC-TFC2016: BitTorrent, Facetime, FTP, Gmail,
MySQL, Outlook, Skype, World of Warcraft — 773k payload-bearing packets), at
increasing background ratios, and reports:

* **wall-clock** (median ± stdev over randomized, interleaved, warm-started runs),
* **startup** (median wall-clock on a one-frame PCAP) and **net** = wall − startup,
  which separates e.g. Zeek's script compilation and OpenGFW's fixed 1 s replay
  drain from steady-state analysis,
* **CPU** (user+sys) and **peak RSS**,
* **µs/packet** and **throughput** derived from net time,
* **TPR/TNR** on the labelled flows (re-indexed into the mixed file), and
* **background_flagged** — how many *unlabelled* real flows each tool acted on
  (e.g. an SNI censor legitimately matching `mail.google.com` in the Gmail capture).

Mixes are declared in `mixes.conf`; scenarios and tools come from the scenario
directories' `scenario.conf` exactly as in Table 4, so a tool's implementation is
never changed between the synthetic and the real-traffic study.

## Running

```bash
nix develop .#experiments
bash experiments/08_real_traffic/scripts/prepare.sh      # fetch dataset (~140 MB), build mixes
bash experiments/08_real_traffic/scripts/run.sh 3        # 3 iterations per tool
python3 experiments/08_real_traffic/scripts/analyze.py   # results/real_traffic.{csv,json}
```

Subsets: `SCENARIOS="03_tls_sni" MIXES="bg0 bg90k" TOOLS="PyCL Zeek" bash …/run.sh`.

## Layout

```
mixes.conf            background mix definitions (NAME=packets)
scripts/prepare.sh    dataset fetch + interleaving (datasets/interleave.py)
scripts/run.sh        harness driver (common/showcase.sh per scenario × mix)
scripts/analyze.py    aggregation -> results/real_traffic.{csv,json}
pcap/                 generated mixes (git-ignored)
results/<scenario>/<mix>/   raw_timings.csv, table4.json, accuracy.json, tool outputs
results/real_traffic.csv    aggregated table
```
