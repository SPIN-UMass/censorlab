# 10 — Live NFQ end-to-end evaluation

Reviewer A: "the NFQ experiments have a setup but no results" (MR2).  This
experiment runs CensorLab as an in-path censor (Tap/NFQ mode) between a client
and a server in Docker and measures, for each Table 4 scenario and censor variant:

* **TPR/TNR** of the live censorship decision (the scenario's traffic generator
  opens real connections; a forbidden one must be reset/dropped/poisoned),
* **per-connection latency** (200 sequential HTTP request/response pairs through
  the censor, median and p95),
* **bulk throughput** (iperf3, 5 s) and retransmissions.

Variants: `none` (plain forwarding, no CensorLab process), `null` (CensorLab NFQ
with an empty program — the cost of queueing every packet to user space),
`pycl` and `censorlang` (the scenario's programs).

Topology (`docker-compose.yml`): client 172.30.0.10 → censor 172.30.0.2 →
server 172.30.0.20 on one bridge, with /32 host routes via the censor and ICMP
redirects disabled, so every packet is forwarded by the censor container
(ip_forward=1; CensorLab hooks raw/PREROUTING).  The same topology is shipped as
the documentation example `docker/docker-compose.live.yml`.

```bash
nix build .#docker-live && docker load < result
bash experiments/10_nfq_end_to_end/scripts/run.sh [N_REQUESTS] [PROBE_N] [IPERF_SECONDS]
python3 experiments/10_nfq_end_to_end/scripts/analyze.py    # results/nfq_end_to_end.{csv,json}
```

Results per (scenario, variant) are in `results/<scenario>/<variant>/`
(`live_eval_results.csv`, `latency.csv`, `iperf.json`, `client.log`, `censor.log`).

Findings that only live mode could reveal (all fixed in this revision): a PyCL
program that drops a connection's first data packet but not the TCP
retransmission; a CensorLang DNS program whose word list, lacking a port guard,
matched bulk TCP payloads; and RST injection that spoofed the Ethernet source
and thereby poisoned the learning bridge it was attached to.
