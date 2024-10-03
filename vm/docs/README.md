# CensorLab: A Generic Testbed for Censorship Emulation

# About
Censorlab is a censorship emulation platform.

# Updating this VM
The CensorLab experimental VM uses NixOS, a declarative operating system which allows for very strong reproducibility. To update the VM, run the `censorlab-update` command

# Configuration
Configuration of the censor is done in `TOML` files and passed in with the `-c` flag. See `censor.toml` for configuration options. You probably want to copy censor.toml to your own config file and pass it in. The default censor.toml uses

* `censor-scripts/cl-python/shadowsocks_ml.py`
* `models/poison_test/poisoned.onnx.ml`

# Censor Programs
A Censor Program is a Python script in the following form:
```python
# Initialize global variables, which will be accessible for all subsequent executions within the same connection
a = 1

# This function processes packets
def process(packet):
    # To allow a packet, return None or "allow"
    # return None
    # return
    # return "allow"
    # Python functions implicitly return None if no return statement is executed, so you can also use that
    # To drop a packet,  
    # return "drop"
```
Some example programs are provided in `/etc/censorlab-demos`

Properties of `packet` are listed in the Python API section.

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
 * `packet.timestamp` - Unix timestamp of the packet
 * `packet.direction` - Direction of the packet. Client to wan = 1. unknown = 0. wan to client = -1

## ip
 * `packet.ip.header_len` - Length of IP header
 * `packet.ip.total_len` - Total length of ip packet
 * `packet.ip.ttl` - TTL of IP packet
 * `packet.ip.src` - Source IP address
 * `packet.ip.dst` - Destination IP address

## tcp
 * `packet.tcp.src` - Source port
 * `packet.tcp.dst` - Destination port 
 * `packet.tcp.seq` - TCP SEQ number
 * `packet.tcp.ack` - TCP ACK number
 * `packet.tcp.header_len` - TCP header length
 * `packet.tcp.urgent_at` - TCP urgent at flat
 * `packet.tcp.window_len` - TCP window length
 * *TCP Flags*
     * `packet.tcp.flags.fin`
     * `packet.tcp.flags.syn`
     * `packet.tcp.flags.rst`
     * `packet.tcp.flags.psh`
     * `packet.tcp.flags.ack`
     * `packet.tcp.flags.urg`
     * `packet.tcp.flags.ece`
     * `packet.tcp.flags.cwr`
     * `packet.tcp.flags.ns`

## udp
 * `packet.udp.src` - Source port
 * `packet.udp.dst` - Destination port 
 * `packet.udp.length` - UDP total length
 * `packet.udp.checksum` - UDP checksum

## Payload properties, generic to TCP and UDP
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
* `dns.id` - int, ID of the DNS packet, used for matching requests to responses
* `dns.query` - bool, whether the DNS packet is a query
* `dns.opcode` - str, see https://docs.rs/dns-parser/latest/dns_parser/enum.Opcode.html
* `dns.authoritative` - bool, whether the response is authoritative
* `dns.truncated` - bool - Whether the response was truncated 
* `dns.recursion_desired` - bool, Whether recursion is requested
* `dns.recursion_available` - bool, Whether recursion is available
* `dns.authenticated_data` - bool, Whether the response is authenticated
* `dns.checking_disabled` - bool, whether DNS response should be sent whether or not validation was successfully performed
* `dns.response_code` - str, see https://docs.rs/dns-parser/latest/dns_parser/enum.ResponseCode.html
* `dns.questions` - a list of DNS questions in the packet
* `dns.questions[n].qname` - str, the name requested 
* `dns.questions[n].prefer_unicast` - bool, whether to prefer unicast addresses
* `dns.questions[n].qtype`  - str, DNS query type, see https://docs.rs/dns-parser/latest/dns_parser/enum.QueryType.html
* `dns.questions[n].qclass` - str, DNS query class, see https://docs.rs/dns-parser/latest/dns_parser/enum.QueryClass.html
* `dns.answers` - a list of DNS answers
* `dns.answers[n].name` - name answering to
* `dns.answers[n].multicast_unique` - bool, related to cache in mdns 
* `dns.answers[n].cls` - str, DNS record class, see https://docs.rs/dns-parser/latest/dns_parser/enum.Class.html
* `dns.answers[n].ttl` - int, TTL of the response
* `dns.answers[n].data` - A tuple of the RData class (e.g. "A", "AAAA") with its fields
* `dns.nameservers` - Same format as answers
* `dns.additional` - Same format as answers
* `dns.opt` - DNS Options, see https://docs.rs/dns-parser/latest/dns_parser/rdata/opt/struct.Record.html
* `dns.opt.udp` 
* `dns.opt.extrcode` 
* `dns.opt.version` 
* `dns.opt.flags` 
* `dns.opt.data` 
