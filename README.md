# CensorLab: A Generic Testbed for Censorship Emulation

**[Documentation](https://censorlab.cs.umass.edu/)**

# About



# Configuration
Configuration of the censor is done in `TOML` files and passed in with the `-c` flag. See `censor.toml` for configuration options. You probably want to copy censor.toml to your own config file and pass it in. See the demos folder for more information.

# Running in tap mode
```sh
cargo run --release --bin censorlab -- -c censor.toml nfq 
```
To list all the configurable options:
```sh
cargo run --release --bin censorlab -- --help
cargo run --release --bin censorlab -- nfq --help
```

# Running with Docker

CensorLab provides a Docker setup for running without a local Nix or Rust toolchain.

### Quick start

```bash
# Interactive shell with censorlab on PATH
bash docker/censorlab.sh --shell

# Run a demo in NFQ mode (requires Linux host with xt_NFQUEUE)
sudo bash docker/censorlab.sh -c demos/dns_blocking/censor.toml nfq

# Analyze a PCAP file
bash docker/censorlab.sh -c demos/http_blocking/censor.toml pcap traffic.pcap
```

The wrapper script auto-detects NFQ vs PCAP mode and picks the right Docker Compose service. NFQ mode uses host networking with `NET_ADMIN`/`NET_RAW` capabilities; PCAP mode runs in an isolated container.

### Advanced usage

```bash
# Mount custom configs into the container
DOCKER_ARGS="-v /path/to/my/configs:/censorlab/custom" \
    bash docker/censorlab.sh -c custom/censor.toml nfq

# Force rebuild after source changes
REBUILD=1 bash docker/censorlab.sh --shell

# Use docker compose directly
docker compose -f docker/docker-compose.yml build
docker compose -f docker/docker-compose.yml run --rm censorlab bash
```

# Experiments

Reproducible experiments for evaluation (HTTP keyword filtering, DNS injection, TLS SNI filtering, Shadowsocks detection, ML classification, model extraction, and throughput benchmarks). See [`experiments/README.md`](experiments/README.md) for details on running each experiment.
