# 11 — Circumvention-tool resilience matrix

Reviewer E asked for a research finding beyond re-implementing known techniques.
This experiment runs the *whole corpus* of censor programs against genuine
traffic of three circumvention tools and a real benign control, producing a
tool × strategy matrix of detection (and collateral) rates.

## Traffic

The captures are recorded from the real tools, not synthesized
(`scripts/capture.sh`, Docker image `.#docker-circumvention`):

| set | what is on the wire | how it is produced |
|-----|--------------------|--------------------|
| `shadowsocks` | shadowsocks-rust 1.24, `chacha20-ietf-poly1305`, 60 tunnelled HTTP fetches of 1 KB–1 MB objects | `ssserver` ⇄ `sslocal` (SOCKS5) |
| `obfs4` | lyrebird 0.8.1 obfs4 bridge (`iat-mode=0`), 60 tunnelled fetches | managed-transport server/client, SOCKS5 args per pt-spec |
| `snowflake` | Snowflake 2.x: broker rendezvous over HTTP, WebRTC/DTLS data channel to a standalone proxy, 10 tunnelled fetches | local broker + server + proxy + client |
| `benign` | 50k packets of real application traffic (USTC-TFC2016: BitTorrent, Facetime, FTP, Gmail, MySQL, Outlook, Skype, WoW) | `datasets/fetch_ustc_tfc2016.sh` |

Every flow of a circumvention capture is circumvention traffic, so a censor
action is a correct detection; every action on the benign set is collateral.

## Corpus

`corpus.conf` lists the censor programs (PyCL and CensorLang variants of the
Table 4 scenarios plus the demos: TLS-in-TLS, TSPU TTL normalization,
throttling, QUIC/SNI blocking, mega-GFW).  Each is run unchanged in PCAP mode;
`scripts/matrix.py` counts flagged flows with the shared flow table
(`common/report.py`).

## Running

```bash
nix build .#docker-circumvention && docker load < result
N_FETCHES=60 bash experiments/11_resilience_matrix/scripts/capture.sh   # pcap/*.pcap
nix develop .#experiments
python3 experiments/11_resilience_matrix/scripts/matrix.py               # results/resilience_matrix.{csv,json}
```

## Layout

```
corpus.conf / traffic.conf   what is evaluated against what
docker-compose.yml           capture topology (client ⇄ server, real tools)
scripts/server.sh            origin + Shadowsocks/obfs4/Snowflake servers (+ broker, proxy)
scripts/client.sh            tunnels fetches through each tool under tcpdump
scripts/socks_fetch.py       SOCKS5 (RFC 1929 auth for pluggable-transport args) HTTP fetch
scripts/capture.sh           host-side driver
scripts/matrix.py            corpus × traffic evaluation
pcap/                        captures (git-ignored)
results/                     resilience_matrix.csv/json + per-cell censorlab output
```
