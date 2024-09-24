# CensorLab: A Generic Testbed for Censorship Emulation

# About
Censorlab is a censorship emulation platform.

# Updating this VM
To update the vm, run `censorlab-update`

# Configuration
Configuration of the censor is done in `TOML` files and passed in with the `-c` flag. See `censor.toml` for configuration options. You probably want to copy censor.toml to your own config file and pass it in. The default censor.toml uses

* `censor-scripts/cl-python/shadowsocks_ml.py`
* `models/poison_test/poisoned.onnx.ml`

# Running in this VM
```

To start CensorLab (in NFQ mode which intercepts the Linux firewall) using a sample censor (DNS blocking of google.com)
```sh
censorlab -c /etc/censorlab-demos/dns_blocking/censor.toml nfq
```

You may read this censor.toml as an example of what a CensorLab scenario looks like

To list all CensorLab's arguments
```sh
censorlab --help
censorlab nfq --help
```


# Python API
Censor programs are operated in two parts:
* Upon connection, the entire script is executed. This can be used for initialization, etc
* For each packet, including the first packet, the `process` function is executed

You likely want to begin your program with
```python
from rust import Packet, Model, regex
```
to ensure all appropriate methods are in scope

The interfaces that may be accessed to read metadata from each packet are:

## packet
 * global variable, but passed to the function
 * `packet.timestamp` - Unix timestamp of the packet
 * `packet.direction` - Direction of the packet. Client to wan = 1. unknown = 0. wan to client = -1
 * `ip.header_len` - Length of IP header
 * `ip.total_len` - Total length of ip packet
 * `ip.ttl` - TTL of IP packet
 * `packet.tcp.seq` - TCP SEQ number
 * `packet.tcp.ack` - TCP ACK number
 * `packet.tcp.header_len` - TCP header length
 * `packet.tcp.urgent_at` - TCP urgent at flat
 * `packet.tcp.window_len` - TCP window length
TCP Flags:
     * `packet.tcp.flags.fin,
     * `packet.tcp.flags.syn`
     * `packet.tcp.flags.rst`
     * `packet.tcp.flags.psh`
     * `packet.tcp.flags.ack`
     * `packet.tcp.flags.urg`
     * `packet.tcp.flags.ece`
     * `packet.tcp.flags.cwr`
     * `packet.tcp.flags.ns`
 * `udp.length` - UDP total length
 * `udp.checksum` - UDP checksum
 * `packet.payload` - payload body, regardless of transport protocol
 * `packet.payload_len` - payload length, regardless of transport protocol
 * `packet.payload_entropy` - payload entropy regardless of transport protocol
 * `packet.payload_avg_popcount` - payload average popcount, regardless of transport protocol

## model
 * global variable
 * `model.evaluate("name", input)`
    * `name` - the name of the model, as in the config file
    * `data` - a python list of floats. It is assumed that the model input has shape NxM (the example is 1x90), in which case the python list should have length 90
    * `RETURNS` - a list of floats, from the `probability` output of the ONNX model

## regex
 * `from rust import regex`
 * `re = regex("foo|bar")`
 * `re.ismatch(b)` - accepts a python-style byte array, returns whether the regex matches. useful for payload

## DNS
This sample code will allow you to get started with parsing DNS packets:
```python
from dns import parse as parse_dns

def process(packet):
    udp = packet.udp
    if udp and 53 in [udp.src, udp.dst]:
        dns = parse_dns(packet.payload)
```
properties of the dns payload include:
* `dns.id`
* `dns.query`
* `dns.opcode`
* `dns.authoritative`
* `dns.truncated`
* `dns.recursion_desired`
* `dns.recursion_available`
* `dns.recursion_available`
* `dns.authenticated_data`
* `dns.checking_disabled`
* `dns.response_code`
* `dns.questions` - a list of DNS questions in the packet
* `dns.questions[n].qname` 
* `dns.questions[n].prefer_unicast` 
* `dns.questions[n].qtype` 
* `dns.questions[n].qclass` 
* `dns.answers` - a list of DNS answers
* `dns.answers[n].name`
* `dns.answers[n].multicast_unique`
* `dns.answers[n].cls`
* `dns.answers[n].ttl`
* `dns.answers[n].data` - A tuple of the RData class (e.g. "A", "AAAA") with its fields
* `dns.nameservers` - Same format as answers
* `dns.additional` - Same format as answers
* `dns.opt` - DNS Options
* `dns.opt.udp` 
* `dns.opt.extrcode` 
* `dns.opt.version` 
* `dns.opt.flags` 
* `dns.opt.data` 
