# Censorlab
As far as I know, the only dependency is a rust toolchain (current stable)

# About


# Recommended environment
Turn off offloading to entire accurate packet data
```
sudo ethtool -K eth0 tso off gro off gso off lro off
```

# Configuration
Configuration of the censor is done in `TOML` files and passed in with the `-c` flag. See `censor.toml` for configuration options. You probably want to copy censor.toml to your own config file and pass it in. The default censor.toml uses
* `censor-scripts/cl-python/shadowsocks_ml.py`
* `models/poison_test/poisoned.onnx.ml`

# Running in tap mode
In a system where `eth0` is the interface you want to tap and 10.0.0.78 is the ip of the "client"
```sh
cargo run --release --bin censorlab -- -c censor.toml tap eth0 10.0.0.78
```
To list all the configurable options:
```sh
cargo run --release --bin censorlab -- --help
cargo run --release --bin censorlab -- nfq --help
```


# Python API
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

