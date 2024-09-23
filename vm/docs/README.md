# CensorLab: A Generic Testbed for Censorship Emulation

# About
Censorlab is a censorship emulation platform.

# Configuration
Configuration of the censor is done in `TOML` files and passed in with the `-c` flag. See `censor.toml` for configuration options. You probably want to copy censor.toml to your own config file and pass it in. The default censor.toml uses

* `censor-scripts/cl-python/shadowsocks_ml.py`
* `models/poison_test/poisoned.onnx.ml`

# Running in tap mode
Censorlab uses netfilter queues to intercept traffic. To start intercepting traffic in this vm, run
```sh
cl_nftables.sh start
```
While this script is started,

* Before CensorLab is started - Traffic will all fail due to no program listening on the given queue
* While CensorLab is running - Traffic may be blocked by the censor program

Make sure you retain access to this virtual machine using a virtualized display, as SSH may cease to function

To stop forwarding traffic to the queue:
```sh
cl_nftables.sh stop
```

In a system where `enp0s3` is the interface you want to tap and 10.0.2.15 is the ip of the client (e.g. this VM), the command to start censorlab using the provided censor.toml is
```sh
censorlab -c censor.toml tap enp0s3 10.0.2.15
```

You may verify the interface name and IP address of the VM using
```sh
ip addr
```

To list all the configurable options:
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

