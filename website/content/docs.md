+++
title = "CensorLab Documentation"
template = "docs.html"
+++

# CensorLab Reference Documentation

This document covers general usage of CensorLab, the configuration file format, the Python censor language (PyCL) API, and the CensorLang DSL.

---

# General Usage

CensorLab is a censorship emulation testbed that intercepts network packets and processes them through configurable layers with optional Python scripts or ML models for custom censorship logic.

## Installation

The easiest way to get started is with the pre-built VM images available on the [VM Info](/vm-info/) page. These provide a self-contained environment with everything pre-configured.

To build from source, you need a Rust toolchain. Nix users can run `nix develop` for a complete environment.

```bash
# Build (release mode recommended for performance)
cargo build --release

# Build with wire mode support
cargo build --release --features wire

# Set required network capabilities
sudo ./set_permissions.sh

# Run tests
cargo test --verbose
```

The `set_permissions.sh` script grants `CAP_NET_ADMIN` and `CAP_NET_RAW` capabilities to the binary, which are required for packet interception.

## Environment Setup

For accurate packet data, disable hardware offloading on the network interface CensorLab will use:

```bash
sudo ethtool -K eth0 tso off gro off gso off lro off
```

Replace `eth0` with your actual interface name.

## Running CensorLab

CensorLab has three execution modes: **NFQ** (netfilter queue), **PCAP** (offline analysis), and **Wire** (inline bridge). Each mode is selected as a subcommand.

### Quick Start

```bash
# Run with a Python script in NFQ mode
censorlab -p censor.py nfq

# Run with a full configuration file
censorlab -c censor.toml nfq

# Analyze a saved packet capture
censorlab -c censor.toml pcap capture.pcap 192.168.1.100
```

### Global Options

| Flag | Description |
|------|-------------|
| `-c, --config-path <PATH>` | Path to the TOML configuration file |
| `-p, --program <PATH>` | Path to a censor script (overrides the one in config) |
| `-v, --verbosity <LEVEL>` | Log verbosity: `trace`, `debug`, `info`, `warn`, `error` (default: `info`) |
| `--ipc-port <PORT>` | Port for IPC commands |

### NFQ Mode

The most common mode. CensorLab hooks into the Linux netfilter queue to intercept live traffic. It automatically creates iptables rules on startup and removes them on shutdown.

```bash
censorlab -c censor.toml nfq [OPTIONS] [INTERFACE]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--client-ip <IP>` | *(auto-detected)* | IP address considered the "client" for direction calculation |
| `--no-dir-action <ACTION>` | `ignore` | Action for traffic without a determinable direction |
| `--iptables-table <TABLE>` | `raw` | iptables table to intercept at |
| `--iptables-chain-in <CHAIN>` | `PREROUTING` | iptables chain for inbound packets |
| `--iptables-chain-out <CHAIN>` | `OUTPUT` | iptables chain for outbound packets |
| `--queue-num-in <NUM>` | `0` | NFQUEUE number for inbound packets |
| `--queue-num-out <NUM>` | `1` | NFQUEUE number for outbound packets |
| `--force-iptables` | | Force rule insertion even if conflicting NFQUEUE rules exist |
| `[INTERFACE]` | *(auto-detected)* | Network interface to use for sending packets |

CensorLab determines packet direction by comparing source/destination addresses against the client IP. Traffic from the client IP is considered client-to-WAN; traffic to it is WAN-to-client.

### PCAP Mode

Analyzes a saved packet capture file offline. CensorLab processes each packet through the censor pipeline and logs what actions it *would* have taken.

```bash
censorlab -c censor.toml pcap <PCAP_PATH> <CLIENT_IP>
```

| Argument | Description |
|----------|-------------|
| `<PCAP_PATH>` | Path to the `.pcap` file to analyze |
| `<CLIENT_IP>` | Client IP address for direction calculation |

### Wire Mode

In wire mode, CensorLab sits between two network interfaces (WAN and client) and forwards packets between them. It can drop, delay, or modify packets inline. This mode requires the `wire` feature flag at build time.

```bash
cargo build --release --features wire
censorlab -c censor.toml wire <WAN_INTERFACE> <CLIENT_INTERFACE> [OPTIONS]
```

| Argument / Flag | Default | Description |
|-----------------|---------|-------------|
| `<WAN_INTERFACE>` | | WAN-side network interface |
| `<CLIENT_INTERFACE>` | | Client-side network interface |
| `--wan-packets <NUM>` | `1` | Max packets from WAN before polling client |
| `--client-packets <NUM>` | `1` | Max packets from client before polling WAN |

## Packet Processing Pipeline

Packets flow through a layered processing pipeline. Each layer can allow, drop, reset, or ignore packets before they reach the censor script:

```
Network Input (NFQ / Wire / PCAP)
  → Ethernet layer (MAC allowlist/blocklist)
    → ARP handling
      → IP layer (IP allowlist/blocklist)
        → ICMP handling
          → TCP/UDP layer (port allowlist/blocklist)
            → Censor script (Python or CensorLang)
              → Action (Allow / Drop / Reset / Ignore)
```

If a packet matches a blocklist at any layer, the configured action is taken immediately and the packet does not reach the censor script. Allowlists work inversely — only listed values pass through.

## Demos

The [demos directory](https://github.com/SPIN-UMass/censorlab/tree/main/demos) contains example scenarios, each with a `censor.toml` and associated scripts/models:

```bash
# DNS blocking
censorlab -c demos/dns_blocking/censor.toml nfq

# HTTP blocking
censorlab -c demos/http_blocking/censor.toml nfq

# IP blocking
censorlab -c demos/ip_blocking/censor.toml nfq
```

Paths in `censor.toml` are relative to the TOML file itself, including paths to censor scripts and ML models.

---

# Configuration Reference

CensorLab is configured via TOML files, passed with the `-c` flag. Paths to scripts and models within the config are resolved **relative to the config file location**.

## `[execution]`

Controls which scripting engine to use and global execution parameters.

| Key             | Type     | Default    | Description |
|-----------------|----------|------------|-------------|
| `mode`          | string   | `"Python"` | Execution mode: `"Python"` or `"CensorLang"` |
| `script`        | string   | *(none)*   | Path to the censor script (relative to config file) |
| `hash_seed`     | integer  | `1337`     | Hash seed for Python VM reproducibility |
| `reset_repeat`  | integer  | `5`        | Number of times to repeat sending a TCP RST packet |

## Layer Filtering

CensorLab processes packets through a layered pipeline. Each layer can have allowlists and blocklists that act before the script is invoked.

### `[ethernet]`

| Key           | Type       | Description |
|---------------|------------|-------------|
| `unknown`     | action     | Action for unknown Ethernet frame types |
| `allowlist`   | list block | MAC address allowlist |
| `blocklist`   | list block | MAC address blocklist |

### `[arp]`

| Key      | Type   | Description |
|----------|--------|-------------|
| `action` | action | Action for all ARP traffic (default: `"None"`) |

### `[ip]`

| Key           | Type       | Description |
|---------------|------------|-------------|
| `unknown`     | action     | Action for unknown IP next-header protocols |
| `allowlist`   | list block | IP address allowlist |
| `blocklist`   | list block | IP address blocklist |

IP addresses are strings like `"192.168.1.1"` or `"::1"`.

### `[icmp]`

| Key      | Type   | Description |
|----------|--------|-------------|
| `action` | action | Action for all ICMP traffic (default: `"None"`) |

### `[tcp]` / `[udp]`

| Key                  | Type       | Description |
|----------------------|------------|-------------|
| `port_allowlist`     | list block | Port number allowlist |
| `port_blocklist`     | list block | Port number blocklist |
| `ip_port_allowlist`  | list block | IP:port pair allowlist |
| `ip_port_blocklist`  | list block | IP:port pair blocklist |

Port lists contain integers (e.g. `[80, 443]`). IP:port pairs are strings like `"10.0.0.1:80"` or `"[::1]:443"`.

### List Block Format

Allowlist and blocklist sections share a common format:

```toml
[ip.blocklist]
list = ["192.168.1.1", "10.0.0.0"]
action = "Drop"
```

| Key      | Type          | Default  | Description |
|----------|---------------|----------|-------------|
| `list`   | array         | `[]`     | Values to match against |
| `action` | action string | `"None"` | Action to take on match |

## `[models.<name>]`

Defines ONNX models available to censor scripts.

| Key    | Type   | Description |
|--------|--------|-------------|
| `path` | string | Path to the `.onnx.ml` model file (relative to config file) |

## Actions

Actions control what happens to a packet at a given processing layer.

| Action     | Description |
|------------|-------------|
| `"None"`   | Continue processing through subsequent layers |
| `"Ignore"` | Forward the packet immediately, skip further processing |
| `"Drop"`   | Silently drop the packet |
| `"Reset"`  | Send TCP RST packets in both directions (only valid for TCP-layer lists) |

`"Reset"` is only valid on `[tcp]` lists. Using it on `[ethernet]`, `[arp]`, `[ip]`, or `[icmp]` sections will produce a validation error.

## Example Configuration

```toml
[execution]
mode = "Python"
script = "censor.py"
hash_seed = 1337
reset_repeat = 5

[ip.blocklist]
list = ["192.168.31.1"]
action = "Reset"

[tcp.port_blocklist]
list = [80]
action = "Reset"

[tcp]
ip_port_allowlist = { list = ["10.0.0.1:443"] }

[models.classifier]
path = "models/classifier.onnx.ml"
```

---

# PyCL (Python Censor Language) Reference

PyCL is CensorLab's Python scripting API, powered by RustPython. Scripts run per-connection inside an embedded Python VM.

## Lifecycle

1. **Connection init**: On the first packet for a new connection, the entire script file is executed. Use this for initialization (global variables, imports, etc.).
2. **Per-packet processing**: For every packet (including the first), the `process(packet)` function is called.
3. **Return value**: The return value of `process()` determines the action for that packet.

## Imports

```python
from rust import Packet, Model, regex
```

This brings all core types into scope. Protocol-specific modules are imported separately:

```python
from dns import parse as parse_dns
from tls import parse_client_hello, parse_client_hello_message
from quic import parse_initial
```

## Return Values

The `process()` function should return one of:

| Return value   | Effect |
|----------------|--------|
| `None`         | Allow the packet (continue processing) |
| `"allow"`      | Same as `None` |
| `"drop"`       | Drop the packet silently |
| `"reset"`      | Send TCP RST in both directions (falls back to `"drop"` for non-TCP) |

Any unrecognized string is treated as allow with a warning logged.

## `Packet`

The `packet` object is passed to `process()` and provides read-only access to packet metadata and payload.

### Top-level Attributes

| Attribute               | Type            | Description |
|-------------------------|-----------------|-------------|
| `packet.timestamp`      | `float` or `None` | Unix timestamp of the packet capture |
| `packet.direction`      | `int`           | `1` = client-to-WAN, `0` = unknown, `-1` = WAN-to-client |
| `packet.payload`        | `bytes`         | Transport-layer payload bytes |
| `packet.payload_len`    | `int`           | Length of the payload in bytes |
| `packet.payload_entropy`| `float`         | Shannon entropy of the payload, scaled 0.0–1.0 |
| `packet.payload_avg_popcount` | `float`   | Average number of set bits per byte (0.0–8.0) |
| `packet.ip`             | `IpPacket`      | IP layer metadata |
| `packet.tcp`            | `TcpPacket` or `None` | TCP metadata (None if not TCP) |
| `packet.udp`            | `UdpPacket` or `None` | UDP metadata (None if not UDP) |

### `IpPacket`

Accessed via `packet.ip`.

| Attribute     | Type            | Description |
|---------------|-----------------|-------------|
| `.src`        | `str`           | Source IP address |
| `.dst`        | `str`           | Destination IP address |
| `.header_len` | `int`           | IP header length in bytes |
| `.total_len`  | `int`           | Total IP packet length |
| `.ttl`        | `int`           | Time-to-live / hop limit |
| `.next_header`| `int`           | IP protocol number (6=TCP, 17=UDP) |
| `.version`    | `int`           | IP version (4 or 6) |

**IPv4-only** (return `None` on IPv6):

| Attribute     | Type            | Description |
|---------------|-----------------|-------------|
| `.dscp`       | `int` or `None` | Differentiated Services Code Point |
| `.ecn`        | `int` or `None` | Explicit Congestion Notification |
| `.ident`      | `int` or `None` | Identification field |
| `.dont_frag`  | `bool` or `None`| Don't Fragment flag |
| `.more_frags` | `bool` or `None`| More Fragments flag |
| `.frag_offset`| `int` or `None` | Fragment offset |
| `.checksum`   | `int` or `None` | Header checksum |

**IPv6-only** (return `None` on IPv4):

| Attribute       | Type            | Description |
|-----------------|-----------------|-------------|
| `.traffic_class`| `int` or `None` | Traffic class |
| `.flow_label`   | `int` or `None` | Flow label |
| `.payload_len`  | `int` or `None` | Payload length |

### `TcpPacket`

Accessed via `packet.tcp`. Returns `None` if the packet is not TCP.

| Attribute     | Type       | Description |
|---------------|------------|-------------|
| `.src`        | `int`      | Source port |
| `.dst`        | `int`      | Destination port |
| `.seq`        | `int`      | Sequence number |
| `.ack`        | `int`      | Acknowledgement number |
| `.header_len` | `int`      | TCP header length in bytes |
| `.urgent_at`  | `int`      | Urgent pointer |
| `.window_len` | `int`      | Window size |
| `.flags`      | `TcpFlags` | TCP flags object |

**Method:**

| Method               | Returns | Description |
|----------------------|---------|-------------|
| `.uses_port(port)`   | `bool`  | True if either src or dst equals `port` |

### `TcpFlags`

Accessed via `packet.tcp.flags`. All attributes are `bool`.

| Attribute | Description |
|-----------|-------------|
| `.fin`    | FIN flag    |
| `.syn`    | SYN flag    |
| `.rst`    | RST flag    |
| `.psh`    | PSH flag    |
| `.ack`    | ACK flag    |
| `.urg`    | URG flag    |
| `.ece`    | ECE flag    |
| `.cwr`    | CWR flag    |
| `.ns`     | NS flag     |

### `UdpPacket`

Accessed via `packet.udp`. Returns `None` if the packet is not UDP.

| Attribute  | Type  | Description |
|------------|-------|-------------|
| `.src`     | `int` | Source port |
| `.dst`     | `int` | Destination port |
| `.length`  | `int` | Total UDP datagram length (header + payload) |
| `.checksum`| `int` | UDP checksum |

**Method:**

| Method               | Returns | Description |
|----------------------|---------|-------------|
| `.uses_port(port)`   | `bool`  | True if either src or dst equals `port` |

## DNS Module

Parse DNS packets from raw payload bytes.

```python
from dns import parse as parse_dns

def process(packet):
    udp = packet.udp
    if udp and udp.uses_port(53):
        dns = parse_dns(packet.payload)
        for question in dns.questions:
            if "example.com" in question.qname:
                return "drop"
```

### `DnsPacket`

Returned by `parse(bytes)`.

| Attribute       | Type                   | Description |
|-----------------|------------------------|-------------|
| `.id`           | `int`                  | Query ID |
| `.query`        | `bool`                 | True if this is a query (vs response) |
| `.opcode`       | `str`                  | Opcode (e.g. `"StandardQuery"`) |
| `.authoritative`| `bool`                 | Authoritative answer flag |
| `.truncated`    | `bool`                 | Truncation flag |
| `.recursion_desired`   | `bool`          | Recursion desired flag |
| `.recursion_available` | `bool`          | Recursion available flag |
| `.authenticated_data`  | `bool`          | Authenticated data flag |
| `.checking_disabled`   | `bool`          | Checking disabled flag |
| `.response_code`| `str`                 | Response code (e.g. `"NoError"`) |
| `.questions`    | `list[Question]`       | Question records |
| `.answers`      | `list[ResourceRecord]` | Answer records |
| `.nameservers`  | `list[ResourceRecord]` | Authority records |
| `.additional`   | `list[ResourceRecord]` | Additional records |
| `.opt`          | `Record` or `None`     | OPT pseudo-record |

### `Question`

| Attribute        | Type   | Description |
|------------------|--------|-------------|
| `.qname`         | `str`  | Queried domain name |
| `.prefer_unicast`| `bool` | Unicast response preferred |
| `.qtype`         | `str`  | Query type (e.g. `"A"`, `"AAAA"`) |
| `.qclass`        | `str`  | Query class (e.g. `"IN"`) |

### `ResourceRecord`

| Attribute          | Type   | Description |
|--------------------|--------|-------------|
| `.name`            | `str`  | Record name |
| `.multicast_unique`| `bool` | Multicast unique flag |
| `.cls`             | `str`  | Record class (e.g. `"IN"`) |
| `.ttl`             | `int`  | Time-to-live in seconds |
| `.data`            | `tuple`| Record data as a tagged tuple (see below) |

The `.data` attribute returns a tuple whose first element is the record type string:

| Type    | Format |
|---------|--------|
| A       | `("A", "1.2.3.4")` |
| AAAA    | `("AAAA", "::1")` |
| CNAME   | `("CNAME", "alias.example.com")` |
| MX      | `("MX", preference, "mail.example.com")` |
| NS      | `("NS", "ns1.example.com")` |
| PTR     | `("PTR", "host.example.com")` |
| SOA     | `("SOA", primary_ns, mailbox, serial, refresh, retry, expire, minimum_ttl)` |
| SRV     | `("SRV", priority, weight, port, "target.example.com")` |
| TXT     | `("TXT", [b"text data", ...])` |
| Unknown | `("UNKNOWN",)` |

## TLS Module

Parse TLS ClientHello messages from TCP payload.

```python
from tls import parse_client_hello

def process(packet):
    tcp = packet.tcp
    if tcp and tcp.dst == 443 and packet.payload_len > 0:
        try:
            hello = parse_client_hello(packet.payload)
            if hello.sni and "blocked.com" in hello.sni:
                return "reset"
        except:
            pass
```

### Functions

| Function                         | Description |
|----------------------------------|-------------|
| `parse_client_hello(bytes)`      | Parse from a full TLS record (with record header) |
| `parse_client_hello_message(bytes)` | Parse from the handshake message only (no record header) |

Both return a `ClientHelloInfo`.

### `ClientHelloInfo`

| Attribute            | Type              | Description |
|----------------------|-------------------|-------------|
| `.sni`               | `str` or `None`   | Server Name Indication hostname |
| `.alpn`              | `list[str]`       | ALPN protocol names (e.g. `["h2", "http/1.1"]`) |
| `.client_version`    | `int`             | Legacy TLS version from ClientHello (e.g. `0x0303`) |
| `.supported_versions`| `list[int]`       | Supported TLS versions from extension |
| `.cipher_suites_count` | `int`           | Number of cipher suites offered |
| `.extensions_count`  | `int`             | Number of extensions present |

## QUIC Module

Parse QUIC Initial packets from UDP payload. This decrypts the Initial packet using the QUIC v1 key derivation and extracts the embedded TLS ClientHello.

```python
from quic import parse_initial

def process(packet):
    udp = packet.udp
    if udp and udp.uses_port(443) and packet.payload_len > 0:
        try:
            info = parse_initial(packet.payload)
            if info.sni and "blocked.com" in info.sni:
                return "drop"
        except:
            pass
```

### `QuicInitialInfo`

Returned by `parse_initial(bytes)`.

| Attribute  | Type            | Description |
|------------|-----------------|-------------|
| `.version` | `int`           | QUIC version number |
| `.dcid`    | `bytes`         | Destination Connection ID |
| `.scid`    | `bytes`         | Source Connection ID |
| `.sni`     | `str` or `None` | SNI from embedded TLS ClientHello |
| `.alpn`    | `list[str]`     | ALPN from embedded TLS ClientHello |

## Regex

Byte-level regular expression matching using Rust's regex engine.

```python
from rust import regex

re = regex(r"Host:\s+example\.com")

def process(packet):
    if re.is_match(packet.payload):
        return "reset"
```

### `regex(pattern)` → `Regex`

| Method              | Returns | Description |
|---------------------|---------|-------------|
| `.is_match(bytes)`  | `bool`  | True if the pattern matches anywhere in the byte string |

## Model

Evaluate ONNX models defined in the configuration file.

```python
from rust import Model

def process(packet):
    features = [packet.payload_len, packet.payload_entropy]
    # Pad to expected input size
    features += [0.0] * (90 - len(features))
    result = model.evaluate("classifier", features)
    if result[0] > 0.5:
        return "drop"
```

The `model` variable is automatically available in the `process()` scope after initialization.

### `model.evaluate(name, data)` → `list[float]`

| Parameter | Type          | Description |
|-----------|---------------|-------------|
| `name`    | `str`         | Model name as defined in `[models.<name>]` |
| `data`    | `list[float]` | Input feature vector (must match model's expected input size) |

Returns a list of floats from the model's probability output.

## Complete PyCL Example

```python
from rust import Packet, Model, regex
from dns import parse as parse_dns
from tls import parse_client_hello

blocked_domains = ["example.com", "blocked.org"]
http_re = regex(rb"Host:\s+blocked\.org")

def process(packet):
    # Block DNS queries for blocked domains
    udp = packet.udp
    if udp and udp.uses_port(53):
        try:
            dns = parse_dns(packet.payload)
            for q in dns.questions:
                for domain in blocked_domains:
                    if domain in q.qname:
                        return "drop"
        except:
            pass
        return

    # Block TLS connections to blocked domains
    tcp = packet.tcp
    if tcp and tcp.dst == 443 and tcp.flags.syn == False and packet.payload_len > 0:
        try:
            hello = parse_client_hello(packet.payload)
            if hello.sni:
                for domain in blocked_domains:
                    if domain in hello.sni:
                        return "reset"
        except:
            pass

    # Block HTTP by Host header
    if tcp and tcp.uses_port(80):
        if http_re.is_match(packet.payload):
            return "reset"

    # Drop high-entropy traffic (possible encrypted tunnel)
    if packet.payload_entropy > 0.95 and packet.payload_len > 200:
        result = model.evaluate("classifier", [
            float(packet.payload_len),
            packet.payload_entropy,
            packet.payload_avg_popcount,
        ] + [0.0] * 87)
        if result[0] > 0.8:
            return "drop"
```

---

# CensorLang Reference

CensorLang is a linear, register-based DSL for writing censor programs. It is designed for machine-generated censorship strategies (e.g. via genetic programming) but can also be written by hand.

## Overview

- Programs execute **top-to-bottom**, one instruction per line
- The first `RETURN` instruction that executes determines the action for that packet
- If no `RETURN` executes, the packet is allowed
- Each connection gets its own set of registers, preserved across packets

## Configuration

Set `mode = "CensorLang"` in the `[execution]` section:

```toml
[execution]
mode = "CensorLang"
script = "censor.cl"
```

CensorLang programs also respect these environment settings (from the internal program config):

| Setting                | Default | Description |
|------------------------|---------|-------------|
| `field_default_on_error` | `true`  | Return 0/false instead of erroring when accessing a field from the wrong protocol |
| `relax_register_types`   | `false` | Allow writing values into register banks of a different type |

## Syntax

Each line has the form:

```
[if CONDITION:] OPERATION
```

A line is either unconditional (`OPERATION`) or conditional (`if CONDITION: OPERATION`).

## Operations

### `RETURN`

Returns an action for the current packet. The first RETURN that executes wins.

```
RETURN allow
RETURN allow_all
RETURN terminate
```

| Action       | Effect |
|--------------|--------|
| `allow`      | Allow this packet, continue evaluating future packets |
| `allow_all`  | Allow this and all future packets for the connection |
| `terminate`  | Drop this and all future packets for the connection |

Actions are case-insensitive (`ALLOW`, `Allow`, `allow` all work).

### `COPY`

Copy a value into a register.

```
COPY <value> -> <register>
```

Example:
```
COPY field:tcp.payload.len -> reg:i.0
COPY 3.14 -> reg:f.0
COPY True -> reg:b.0
```

### Arithmetic: `ADD`, `SUB`, `MUL`, `DIV`, `MOD`

Perform arithmetic on two values and store the result.

```
ADD <value>, <value> -> <register>
SUB <value>, <value> -> <register>
MUL <value>, <value> -> <register>
DIV <value>, <value> -> <register>
MOD <value>, <value> -> <register>
```

Division and modulo by zero return zero (no error).

Type coercion: when operand types differ, the result is promoted (bool → int → float).

### Bitwise/Logic: `AND`, `OR`, `XOR`

Logical operations on two values, stored as a bool.

```
AND <value>, <value> -> <register>
OR  <value>, <value> -> <register>
XOR <value>, <value> -> <register>
```

Values are converted to bool before the operation (`0` / `0.0` / `false` → false, everything else → true).

### `NOOP`

No operation. Removed by the optimizer.

```
NOOP
```

### `MODEL`

Placeholder for model evaluation (reserved, not yet fully integrated in CensorLang).

```
MODEL
```

## Values

Values can appear as operation inputs or condition operands.

| Syntax            | Type  | Example |
|-------------------|-------|---------|
| Integer literal   | int   | `42`, `-1`, `0` |
| Float literal     | float | `3.14`, `0.5`, `-1.0` |
| `True` / `False`  | bool  | `True` |
| `field:<path>`    | varies| `field:tcp.payload.len` |
| `reg:<type>.<N>`  | varies| `reg:f.0`, `reg:i.3`, `reg:b.1` |

## Registers

Registers are per-connection persistent storage, organized into three typed banks:

| Prefix   | Type  | Default value |
|----------|-------|---------------|
| `reg:f.N`| float | `0.0`         |
| `reg:i.N`| int   | `0`           |
| `reg:b.N`| bool  | `false`       |

The default bank size is 16 registers per type. Writing a value to a register of the wrong type is an error unless `relax_register_types` is enabled.

## Fields

Fields read packet metadata. Accessing a field from the wrong protocol (e.g. `field:tcp.seq` on a UDP packet) produces an error, or returns `0`/`false` if `field_default_on_error` is enabled.

### Environment

| Field                   | Type | Description |
|-------------------------|------|-------------|
| `field:env.num_packets` | int  | Number of packets processed on this connection |

### General

| Field             | Type  | Description |
|-------------------|-------|-------------|
| `field:timestamp` | float | Packet capture timestamp |

### IP (all versions)

| Field               | Type | Description |
|---------------------|------|-------------|
| `field:ip.header_len` | int  | IP header length in bytes |
| `field:ip.total_len`  | int  | Total IP packet length |
| `field:ip.hop_limit`  | int  | TTL / hop limit |

### IPv4-specific

| Field                  | Type | Description |
|------------------------|------|-------------|
| `field:ip4.dscp`       | int  | Differentiated Services Code Point |
| `field:ip4.ecn`        | int  | Explicit Congestion Notification |
| `field:ip4.ident`      | int  | Identification field |
| `field:ip4.dont_frag`  | bool | Don't Fragment flag |
| `field:ip4.more_frags` | bool | More Fragments flag |
| `field:ip4.frag_offset`| int  | Fragment offset |
| `field:ip4.checksum`   | int  | Header checksum |

### IPv6-specific

| Field                    | Type | Description |
|--------------------------|------|-------------|
| `field:ip6.traffic_class`| int  | Traffic class |
| `field:ip6.flow_label`   | int  | Flow label |
| `field:ip6.payload_len`  | int  | Payload length |

### TCP

| Field                  | Type | Description |
|------------------------|------|-------------|
| `field:tcp.seq`        | int  | Sequence number |
| `field:tcp.ack`        | int  | Acknowledgement number |
| `field:tcp.len`        | int  | Total TCP segment length (header + payload) |
| `field:tcp.header.len` | int  | TCP header length |
| `field:tcp.payload.len`| int  | TCP payload length |
| `field:tcp.urgent_at`  | int  | Urgent pointer |
| `field:tcp.window_len` | int  | Window size |

### TCP Flags

| Field                  | Type | Description |
|------------------------|------|-------------|
| `field:tcp.flag.fin`   | bool | FIN flag |
| `field:tcp.flag.syn`   | bool | SYN flag |
| `field:tcp.flag.rst`   | bool | RST flag |
| `field:tcp.flag.psh`   | bool | PSH flag |
| `field:tcp.flag.ack`   | bool | ACK flag |
| `field:tcp.flag.urg`   | bool | URG flag |
| `field:tcp.flag.ece`   | bool | ECE flag |
| `field:tcp.flag.cwr`   | bool | CWR flag |
| `field:tcp.flag.ns`    | bool | NS flag  |

### UDP

| Field              | Type | Description |
|--------------------|------|-------------|
| `field:udp.length` | int  | Total UDP datagram length |
| `field:udp.checksum` | int | UDP checksum |

### Transport Payload

| Field                            | Type  | Description |
|----------------------------------|-------|-------------|
| `field:transport.payload.entropy`| float | Shannon entropy of payload (0.0–1.0) |

## Conditions

Conditions are comparisons between two values:

```
if <value> <operator> <value>: OPERATION
```

### Comparison Operators

| Operator | Aliases | Description |
|----------|---------|-------------|
| `<`      | `lt`    | Less than |
| `<=`     | `le`    | Less than or equal |
| `>`      | `gt`    | Greater than |
| `>=`     | `ge`    | Greater than or equal |
| `==`     | `eq`    | Equal |
| `!=`     | `ne`    | Not equal |

### Logic Operators

Logic operators treat both operands as booleans.

| Operator | Aliases        | Description |
|----------|----------------|-------------|
| `&&`     | `and`, `op_and`| Logical AND |
| `\|\|`   | `or`, `op_or` | Logical OR |
| `^`      | `xor`, `op_xor`| Logical XOR |
| `nand`   | `op_nand`      | Logical NAND |
| `nor`    | `op_nor`       | Logical NOR |
| `xnor`   | `op_xnor`     | Logical XNOR |

## Compiler Optimizations

CensorLang programs are optimized at load time:

- **Constant folding**: `ADD 2, 3 -> reg:i.0` becomes `COPY 5 -> reg:i.0`
- **Dead code elimination**: Registers that are written but never read are removed
- **NOOP stripping**: All NOOP instructions are removed
- **Always-true condition elimination**: `if 1 == 1: RETURN terminate` becomes `RETURN terminate`
- **Always-false condition elimination**: Lines with always-false conditions are removed entirely
- **Unreachable code removal**: Code after an unconditional `RETURN` is truncated

## Complete CensorLang Example

```
COPY field:tcp.payload.len -> reg:i.0
COPY field:transport.payload.entropy -> reg:f.0
if field:tcp.flag.syn == True: RETURN allow
if reg:i.0 > 200: COPY True -> reg:b.0
if reg:f.0 > 0.95: COPY True -> reg:b.1
if reg:b.0 && reg:b.1: RETURN terminate
```

This program:
1. Copies payload length and entropy into registers
2. Allows SYN packets immediately
3. Flags packets with payload > 200 bytes
4. Flags packets with entropy > 0.95
5. Terminates connections where both flags are set (likely encrypted tunnel traffic)
