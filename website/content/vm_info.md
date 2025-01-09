+++
title = "VM Info"
template = "markdown.html"
+++
# Getting started
To use our VMs, you will need to install [VirtualBox](https://www.virtualbox.org/wiki/Downloads).

Once you have imported the VM, there will be two links on the desktop: one leads to the documentation for CensorLab's API and the VM as a whole, while the other opens a terminal.

We try to distribute updated versions of CensorLab, but you may want to keep the VM updated with the latest version of our system specification. You can do this with the `censorlab-update` command. The password for the `censorlab` user is `c3ns0rl4b612@@!`. This VM runs NixOS, and when running the update command, the system will be declaratively updated to our newest definition. No data will be lost in this process.

# x86\_64
If you are using an x86\_64 system, download the [x86\_64 OVA](https://voyager.cs.umass.edu/vm-images/censorlab.ova) and import it into VirtualBox using the import feature.

# aarch64
If you are using an aarch64 system (e.g. newer Macs), you will have to download the [AARCH64 image](https://voyager.cs.umass.edu/vm-images/censorlab-arm.vmdk) and import it as a drive. This is due to a bug in the Mac version of VirtualBox.
You should use
* 4+ CPU Cores
* 12GB Memory
* OS: Arch Linux (arm64)
as the specs of the VM machine
![Step 1](/images/vm_config1.png)
![Step 2](/images/vm_config2.png)
![Step 3](/images/vm_config3.png)
