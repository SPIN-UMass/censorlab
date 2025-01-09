+++
title = "Getting Started"
template = "markdown.html"
+++

# CensorLab Tutorial
## Installation
The easiest way to get started with CensorLab is to use the VM images [here](/vm-info), which provide an environment for testing CensorLab in a contained environment.

If you would prefer to use your own system, you may folow the run instructions [here](https://github.com/SPIN-UMass/censorlab/blob/main/README.md).

## Usage
CensorLab is a censorship simulation program that runs Python programs (known as Censor Programs) one packet at a time, within the scope of a connection. It is configured using two main files: a configuration file, and a censor program. The configuration file defines things such as default parameters and behaviors. You can find an example of `censor.toml` [here](https://github.com/SPIN-UMass/censorlab/blob/main/censor.toml). The censor program is a Python program (referenced in `censor.toml`) that performs the actual censorship algorithm.

For example, a censor program that drops all packets past the first 3 looks like this
```python
num_packet = 0

def process(packet):
	num_packets += 1
	if num_packets > 3:
		return "drop"
```
Note how we don't return anything unless dropping a packet. This is because the default return value of a function in Python is `None`. In CensorLab, `None` is the same as `"allow"`.


You can see more examples of how to use CensorLab [here](https://github.com/SPIN-UMass/censorlab/tree/main/demos), and a full description of the API [here](http://127.0.0.1:1111/docs/).


## Examples
We provide a wide set of examples for CensorLab [here](https://github.com/SPIN-UMass/censorlab/tree/main/demos) to help you get started with writing censor programs. Each example is a folder containing a configuration file, censor program, and optionally an ML model.
