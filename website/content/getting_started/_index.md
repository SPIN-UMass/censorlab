+++
title = "Getting Started"
template = "markdown.html"
+++

# Getting Started with CensorLab

This guide walks you through installing CensorLab, running your first censor program, and understanding the basics — step by step.

## Step 1: Install CensorLab

### Option A: Docker (Recommended)

Docker is the fastest way to get started. You don't need to install Rust or any dependencies — everything is bundled in the container.

**Prerequisites:** [Docker](https://docs.docker.com/get-docker/) must be installed on your system.

```bash
# Clone the repository
git clone https://github.com/SPIN-UMass/censorlab.git
cd censorlab
git submodule update --init

# Open an interactive shell inside the container
bash docker/censorlab.sh --shell
```

The first run builds the Docker image (this takes a few minutes). Subsequent runs are instant.

### Option B: Build from Source

If you prefer to build natively, you need a Rust toolchain. Nix users can run `nix develop` for a complete environment.

```bash
git clone https://github.com/SPIN-UMass/censorlab.git
cd censorlab
git submodule update --init
cargo build --release
sudo ./set_permissions.sh   # grants CAP_NET_ADMIN + CAP_NET_RAW
```

### Option C: Pre-built VM

We also provide pre-built VM images with everything pre-installed. See the [VM Info](/vm-info/) page for setup instructions. This option is useful for classroom environments or if you want a fully isolated setup.

## Step 2: Understand the Two Config Files

CensorLab uses two files to define censorship behavior:

1. **Configuration file (`censor.toml`)** — Defines execution settings, layer-level filters, and references to the censor script and any ML models.
2. **Censor program (`censor.py`)** — A Python script that implements the actual censorship logic, called once per packet within each connection.

Both files are provided in each of the bundled demos under `demos/`.

## Step 3: Run a Demo

CensorLab ships with several ready-to-use demos. Let's try the DNS blocking demo.

### Using Docker

```bash
# Analyze a PCAP file (no special permissions needed)
bash docker/censorlab.sh -c demos/dns_blocking/censor.toml pcap demos/dns_blocking/example.pcap 192.168.1.100

# Or intercept live traffic (requires host networking)
sudo bash docker/censorlab.sh -c demos/dns_blocking/censor.toml nfq
```

### Using a local build

```bash
# Analyze a PCAP file
censorlab -c demos/dns_blocking/censor.toml pcap demos/dns_blocking/example.pcap 192.168.1.100

# Or intercept live traffic
censorlab -c demos/dns_blocking/censor.toml nfq
```

Other demos you can try:

| Demo | What it does |
|------|-------------|
| `demos/http_blocking/` | Blocks HTTP requests by keyword in the Host header |
| `demos/https_blocking_tls/` | Blocks HTTPS by TLS SNI (Server Name Indication) |
| `demos/ip_blocking/` | Blocks traffic to/from specific IP addresses |
| `demos/quic_blocking/` | Blocks QUIC connections by SNI |
| `demos/shadowsocks_gfw/` | Detects Shadowsocks-like encrypted proxy traffic |
| `demos/mega_gfw/` | Comprehensive GFW emulation (7 techniques combined) |

## Step 4: See Censorship in Action

Let's see what censorship actually feels like. We'll start CensorLab with the HTTPS/TLS blocking demo and try browsing the web with it running.

The `demos/https_blocking_tls/` demo blocks HTTPS connections to `example.com` by inspecting the TLS ClientHello for its SNI (Server Name Indication). Connections to other sites pass through normally — just like a real national firewall that targets specific domains.

### Using Docker

```bash
# Open the CensorLab shell (has host networking + capabilities for NFQ)
bash docker/censorlab.sh --shell

# Inside the container, start CensorLab in the background
censorlab -c demos/https_blocking_tls/censor.toml nfq &

# This works fine — google.com is not on the blocklist:
curl https://google.com

# This will hang — the TLS ClientHello is silently dropped:
curl --max-time 5 https://example.com
# curl: (28) Connection timed out

# When you're done, bring CensorLab back to the foreground and stop it:
fg
# Then press Ctrl+C
```

### Using a local build

```bash
# Start CensorLab in the background
censorlab -c demos/https_blocking_tls/censor.toml nfq &

# This works fine — google.com is not on the blocklist:
curl https://google.com

# This will hang — the TLS ClientHello is silently dropped:
curl --max-time 5 https://example.com
# curl: (28) Connection timed out

# When you're done, bring CensorLab back to the foreground and stop it:
fg
# Then press Ctrl+C
```

### What just happened?

When you ran `curl https://google.com`, the TLS handshake completed normally because the SNI didn't match the blocklist. But when you tried `example.com`, CensorLab saw the TLS ClientHello, extracted the SNI field (`example.com`), matched it against the blocklist, and silently dropped the packet. The TCP connection was established, but the TLS handshake never completed — curl hung waiting for a response that would never come.

This is exactly how real-world SNI-based censorship works: the censor inspects the (unencrypted) SNI in the TLS ClientHello and drops or resets connections to targeted domains.

Take a look at the censor script that made this happen (`demos/https_blocking_tls/https_tls.py`):

```python
from tls import parse_client_hello

def process(packet):
    tcp = packet.tcp
    if tcp and 443 in [tcp.src, tcp.dst]:
        try:
            hello = parse_client_hello(packet.payload)
            if hello.sni and "example.com" in hello.sni:
                return "drop"
        except Exception:
            pass
```

Try changing `"example.com"` to a different domain and re-running to block a different site. Or change `"drop"` to `"reset"` to see what happens when the censor actively tears down the connection instead of silently dropping it.

## Step 5: Write Your First Censor Program

Create a file called `my_censor.py`:

```python
num_packets = 0

def process(packet):
    global num_packets
    num_packets += 1
    if num_packets > 3:
        return "drop"
```

This program allows the first 3 packets of each connection, then drops the rest.

Create a minimal `my_censor.toml`:

```toml
[execution]
mode = "Python"
script = "my_censor.py"
```

Run it:

```bash
# Docker
bash docker/censorlab.sh -c my_censor.toml nfq

# Local build
censorlab -c my_censor.toml nfq
```

### Return values

Your `process()` function controls what happens to each packet:

| Return value | Effect |
|-------------|--------|
| `None` (or no return) | Allow the packet |
| `"allow"` | Same as `None` |
| `"drop"` | Silently drop the packet |
| `"reset"` | Send TCP RST to both sides (TCP only; falls back to drop for UDP) |

### Accessing packet data

CensorLab exposes packet metadata at every layer. Here's a censor that throttles plausibly-encrypted connections:

```python
ctr = 0

def process(packet):
    global ctr
    if packet.payload_len > 1000 and packet.payload_entropy > 0.9:
        ctr += 1
        if ctr % 2 == 0:
            return "drop"
```

Key attributes available on `packet`:

| Attribute | Description |
|-----------|-------------|
| `packet.payload` | Raw payload bytes |
| `packet.payload_len` | Payload length |
| `packet.payload_entropy` | Shannon entropy (0.0–1.0) |
| `packet.direction` | `1` (client→WAN), `-1` (WAN→client), `0` (unknown) |
| `packet.ip.src`, `packet.ip.dst` | Source/destination IP |
| `packet.tcp` / `packet.udp` | TCP/UDP metadata (or `None`) |

See the full [PyCL API reference](/docs/#pycl-python-censor-language-reference) for all attributes.

### Using regex

CensorLab includes a fast regex engine for byte-level matching:

```python
from rust import regex
r = regex(b"Host:\\s+example\\.com")

def process(packet):
    if r.is_match(packet.payload):
        return "reset"
```

### Using protocol parsers

Built-in parsers for DNS, TLS, and QUIC let you inspect application-layer protocols:

```python
from dns import parse as parse_dns

def process(packet):
    if packet.udp and packet.udp.uses_port(53):
        dns = parse_dns(packet.payload)
        for q in dns.questions:
            if "blocked.com" in q.qname:
                return "drop"
```

### Using ML models

CensorLab can run ONNX models for ML-based censorship. See the [model demo](https://github.com/SPIN-UMass/censorlab/tree/main/demos/model) for a Jupyter notebook showing how to train and export a model.

## Step 6: Explore Further

- **[Documentation](/docs/)** — Full reference for configuration, PyCL API, and CensorLang DSL
- **[Demos](https://github.com/SPIN-UMass/censorlab/tree/main/demos)** — 12 example scenarios covering DNS, HTTP, HTTPS, QUIC, IP blocking, SSH detection, encrypted proxy detection, and ML-based classification
- **[Paper](https://arxiv.org/abs/2412.16349)** — The research paper describing CensorLab's design and evaluation
