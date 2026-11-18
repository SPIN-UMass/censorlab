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
| `gfw_esni` | GFW ESNI blocking: a ClientHello with extension `0xffce` is delivered, then the client's packets are dropped (Bock et al. 2020). PyCL only | drop |
| `gfw_quic_sni` | GFW QUIC SNI blocking with its measured quirks: first packet of the flow only, no Initial reassembly, v1 only, source port > destination port (Zohaib et al. 2025). PyCL only | drop |
| `gfw_ftp_smtp` | GFW keyword censorship of FTP and SMTP, without residual censorship (Bock et al. 2020, 2021). Also in CensorLang | reset |
| `gfw_dns_tcp` | GFW censorship of DNS over TCP by connection reset (Bock et al. 2020, 2021). Also in CensorLang | reset |
| `iran_protocol_filter` | Iran's protocol filter: on ports 53/80/443, flows whose first two data packets are not DNS, HTTP or TLS are blackholed for 60 s (Bock et al. 2020). PyCL only | drop |
| `iran_sni_blackhole` | Iran's SNI filtering: the client's packets are blackholed for 180 s, no RST (Bock et al. 2020, 2021). PyCL only | drop |
| `turkmenistan` | Turkmenistan's bidirectional, any-port censorship: DNS answers of 127.0.0.1, RSTs on HTTP Host and TLS SNI, 30 s residual RSTs (Nourin et al. 2023). PyCL only | inject, reset |
| `tspu_quic` | TSPU QUIC blocking by fingerprint: UDP/443, at least 1001 bytes, version 1 (Xue et al. 2022). Also in CensorLang | drop |
| `tspu_sni_delayed_drop` | TSPU "SNI-II": after a forbidden ClientHello five more packets pass, then both directions are dropped (Xue et al. 2022). Also in CensorLang | drop |
| `tspu_vpn` | Russia's 2023 WireGuard/OpenVPN blocking: data packets beyond a threshold after the handshake are dropped (ntc.party, net4people/bbs). CensorLang version covers UDP | drop |
| `tspu_ech` | Russia's blocking of Cloudflare ECH: SNI `cloudflare-ech.com` together with an ECH extension (net4people/bbs). PyCL only | drop |
| `tspu_encrypted_dns` | Russia's 2021 blocking of DoT/DoH resolvers by SNI and of plaintext DNS to 8.8.8.8 (ntc.party, net4people/bbs). Also in CensorLang | reset, drop |
| `openvpn_fingerprint` | OpenVPN opcode fingerprinting over a flow's first 100 packets, including XOR-scrambled OpenVPN (Xue et al. 2022). PyCL only | drop |
| `snowflake_dtls` | DTLS handshake fingerprints used against Snowflake in Russia: `supported_groups` in ServerHello, HelloVerifyRequest (Bocovich et al. 2024). PyCL only | drop |
| `null`, `print` | Pass-through / debugging | — |

Demos marked "also in CensorLang" ship a second config, `censor_lang.toml`, that runs the same technique as a CensorLang program:

`censorlab -c desired_demo/censor_lang.toml nfq`

Each demo's `censor.toml` cites the measurement study or report it follows, and the script's header says which parts of the documented behaviour are and are not emulated.
