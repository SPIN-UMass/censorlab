+++
title = "Getting Started"
template = "markdown.html"
+++

# CensorLab Tutorial
CensorLab is a censorship simulation program that runs Python programs (known as Censor Programs) one packet at a time, within the scope of a connection.

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


We also provide a VirtualBox environment for experimenting with CensorLab. Click [here](/vm-info) for more information.
