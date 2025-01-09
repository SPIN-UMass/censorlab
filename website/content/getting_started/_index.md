+++
title = "Getting Started"
template = "markdown.html"
+++

# CensorLab Tutorial
## Installation
The easiest way to get started with CensorLab is to use the VM images [here](/vm-info), which provide an environment for testing CensorLab in a contained environment.

If you would prefer to use your own system, you may follow the run instructions [here](https://github.com/SPIN-UMass/censorlab/blob/main/README.md).

## Usage
CensorLab is a censorship simulation program that runs Python programs (known as Censor Programs) one packet at a time, within the scope of a connection. It is configured using two main files: a configuration file, and a censor program. The configuration file defines things such as default parameters and behaviors. You can find an example of `censor.toml` [here](https://github.com/SPIN-UMass/censorlab/blob/main/censor.toml). The censor program is a Python program (referenced in `censor.toml`) that performs the actual censorship algorithm.

To run CensorLab in tap mode (e.g., integrated within the system's firewall) and with default settings, simply run
```bash
censorlab -p censor.py nfq
```
where `censor.py` is the path to a censor program. You may also use `-c censor.toml` to use a full configuration file for more options. See `censorlab --help` for all options available to CensorLab.

## Censor Programs
An example censor program that drops all packets past the first 3 looks like this
```python
num_packets = 0

def process(packet):
	num_packets += 1
	if num_packets > 3:
		return "drop"
```
Note how we don't return anything unless dropping a packet. This is because the default return value of a function in Python is `None`. In CensorLab, `None` is the same as `"allow"`.

CensorLab also provides the ability to access various data fields from packets, from link-layer, to transport layer for all packets. For example, this censor program implements a primitive form of throttling for plausibly-encrypted connections.
```python
ctr = 0

def process(packet):
    if packet.payload_len > 1000 and packet.payload_entropy > 7.0:
        ctr += 1
        if ctr % 2 == 0:
            return "drop"
```

While the entire Python standard library is not implemented, CensorLab includes efficient support for regular expressions.
```python
from rust import regex
r = regex("foo|bar")

def process(packet):
    if r.ismatch(packet.payload):
        return "drop"
```

CensorLab also includes support for ML models. See [here](https://TODDO) for a Jupyter notebook that builds models in a way that CensorLab can use.


You can see more examples of how to use CensorLab [here](https://github.com/SPIN-UMass/censorlab/tree/main/demos), and a full description of the API [here](http://127.0.0.1:1111/docs/).


## Examples
We provide a wide set of examples for CensorLab [here](https://github.com/SPIN-UMass/censorlab/tree/main/demos) to help you get started with writing censor programs. Each example is a folder containing a configuration file, censor program, and optionally an ML model.
