# Demos

Each of these demos contains a `censor.toml`, the root file for managing CensorLab's behavior. To run one, just run

`censorlab -c desired_demo/censor.toml nfq`

Paths in censor.toml are relative to the TOML file itself, including for the Censor Program or ML models

## Corpus programs

| Demo | Technique emulated | Actions used |
|------|--------------------|--------------|
| `dns_blocking` | DNS response injection (GFW) | inject |
| `http_blocking` | HTTP keyword / Host filtering | reset |
| `https_blocking` | TLS SNI filtering (substring match on payload) | drop |
| `https_blocking_tls` | TLS SNI filtering (reassembled ClientHello) | reset |
| `quic_blocking` | QUIC Initial SNI filtering | drop |
| `ip_blocking` | IP blocklist (addresses or CIDR subnets, e.g. `"198.51.100.0/24"`) | drop |
| `shadowsocks_gfw` | Fully-encrypted-traffic heuristics (Wu et al. 2023) | drop |
| `shadowsocks_poisoned` | ML classifier with poisoned model | reset |
| `model` | ONNX model inference | drop |
| `mega_gfw` | Combined GFW techniques | all |
| `tls_in_tls` | Tunnelled-TLS (TLS-in-TLS) shape detection as reported for Russia's TSPU (ntc.party, net4people/bbs) | reset |
| `tspu_ttl_normalization` | TSPU-style TTL normalization defeating low-TTL fake-segment desync, plus SNI filtering | rewrite, reset |
| `tspu_fragments` | TSPU-style IPv4 fragment normalization: buffer until complete, first fragment's TTL, 45-fragment limit, 5 s timeout (config only, no script) | rewrite, drop |
| `throttling` | Traffic policing: Russia's 2021 Twitter throttling via added delay | delay |
| `null`, `print` | Pass-through / debugging | — |
