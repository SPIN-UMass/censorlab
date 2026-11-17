# 08 — Real-traffic workloads with background mixes

Addresses meta-review item **MR4** (and reviewers B/D): the Table 4 microbenchmarks
use small synthetic PCAPs that contain nothing but the labelled flows, and
measured Zeek's process startup as analysis time.  This experiment re-runs every
tool from Table 4 on the same labelled scenario flows *interleaved with real
traffic*, at increasing background ratios.  The background is selected with
`BACKGROUND` (default `combined`):

| `BACKGROUND` | source | mix ids / result dirs |
|---|---|---|
| `ustc` | benign half of USTC-TFC2016 (Wang et al., ICOIN 2017): BitTorrent, Facetime, FTP, Gmail, MySQL, Outlook, Skype, World of Warcraft — 773k payload-bearing packets, ~140 MB | `bg0 bg10k bg90k bg390k` (unchanged from the original study) |
| `iscx` | non-VPN application captures of ISCXVPN2016 (Draper-Gil et al., ICISSP 2016): one capture per application (22 apps: streaming, VoIP, chat, e-mail, file transfer; no torrent capture is present in the non-VPN archives), ≤ 20 000 IP frames each | `bg0_iscx …` |
| `combined` | half of every mix's background packets from each dataset, each rescaled onto the scenario's time span and merged | `bg0_combined …` |

ISCXVPN2016 sits behind a registration form and must be downloaded by hand
once; see [../README.md § Background datasets](../README.md#background-datasets)
for the manual step, provenance, licence/citation, and why VPN captures are
excluded.  The ingested captures live outside the repository in
`$ISCXVPN2016_DIR` (default `/mnt/shared/jsheffey/censorlab/datasets/iscxvpn2016`),
reached through the git-ignored symlink `experiments/datasets/iscxvpn2016`.

The study reports:

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
bash experiments/datasets/fetch_iscxvpn2016.sh           # once, after the manual ISCX download
bash experiments/08_real_traffic/scripts/prepare.sh      # fetch/verify datasets, build mixes
bash experiments/08_real_traffic/scripts/run.sh 3        # 3 iterations per tool
python3 experiments/08_real_traffic/scripts/analyze.py   # results/real_traffic.{csv,json}
```

`BACKGROUND=ustc` (or `iscx`) must be given to both `prepare.sh` and `run.sh`;
`analyze.py` picks up every background that has results and adds a
`background` column.  USTC-only runs behave exactly as before (same
`interleave.py` output, byte for byte).

Subsets: `SCENARIOS="03_tls_sni" MIXES="bg0 bg90k" TOOLS="PyCL Zeek" bash …/run.sh`.

The generated mixes in `pcap/` are on the local disk (as before); a full
`prepare.sh` writes ~0.5 GB per background (measured for USTC: 515 MB).

## Layout

```
mixes.conf            background mix definitions (NAME=packets)
scripts/prepare.sh    dataset fetch + interleaving (datasets/interleave.py)
scripts/common.sh     mixes.conf parser, BACKGROUND selection, mix ids
scripts/run.sh        harness driver (common/showcase.sh per scenario × mix)
scripts/analyze.py    aggregation -> results/real_traffic.{csv,json}
pcap/                 generated mixes (git-ignored)
results/<scenario>/<mixid>/ raw_timings.csv, table4.json, accuracy.json, tool outputs
                      (<mixid> = <mix> for ustc, <mix>_iscx / <mix>_combined otherwise)
results/real_traffic.csv    aggregated table
```
