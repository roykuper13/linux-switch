[![Build Status](https://travis-ci.com/roykuper13/linux-switch.svg?branch=master)](https://travis-ci.com/roykuper13/linux-switch)
# linux-switch

linux-switch is a module that let you emulate a network in a linux environment
very easily by creating, connecting and configuring network devices that are represented
as Python objects.

Moreover, linux-switch let you manipulate packets before the network switch forwards
them (see example below). Thus, External binaries/applications that performs
any logic on packets (for example - VLAN Hopping, NAT, etc) can be tested using linux-switch.
Also, linux-switch provide a "Punt-Policies"-like mechanisem, which gives you the option
to filter traffic that the manipulation routine will be recieve.


## Description
linux-switch uses linux's network namespace feature. For each `Device` object that's connected to the
network `Switch` object, the module creates a new network namespace that's connected to the
default network namespace.

The network switch object (`Switch`) has the basic operations required by a real network
switch device, meaning:
1. It manages a table that maps between devices and their vlans + network-namespaces.
2. It doesn't allow packets from one vlan to be transmistted to a different vlan.
3. When connecting `Device`s to the `Switch`, the connection type must be specified (access or trunk).
When using trunk - the switch and the device will send/recieve tagged packet.
When using access - they'll send untagged packets.
4. The switch have "Punt-Policies", which means only filtered packets will be forwarded
to the manipulation routine. The punt-policies feature introduce a `duplicate` mode. When set,
packets that are filtered (using the punt policies) will be processed by both manipulation routine
and switch. When not set, packets will be processed by the manipultion routine only, so that routine
can, for example, drop packets!


## Example

### Basic
```python

from switch import Switch
from device import Device

# Creating a network switch instance
switch = Switch()

# Creating two devices, 'a' and 'b', and assign IP addresses to them
dev1 = Device('a', '192.168.250.1', '255.255.255.0')
dev2 = Device('b', '192.168.250.2', '255.255.255.0')

# Connect dev1 to the network switch.
# dev1 will be part of vlan 20.
# The physical port of the switch is configured to be access,
# meaning the switch and the device do not transmit tagged packets,
# and expect to recieve untagged packets.
# The switch will make sure that dev1 will be able to send/recv packets
# from vlan 20 only.
switch.connect_device_access(dev1, 20)

# Connect dev2 to the network switch.
# dev2 will also be part of vlan 20.
# The physical port of the switch is configured to be trunk,
# meaning the switch and the device transmits and recieves tagged packets (dot1q).
switch.connect_device_trunk(dev2, 20)
```

From that point, you can run whatever you want from the devices context.
For example:

```python
# Ping to the second device (we're able to do that since both devices
# are in the same vlan).
dev1.run_from_namespace('ping -c 1 192.168.250.2')

# Open a terminal (gnome-terminal is given as an example)
dev2.run_from_namespace('dbus-launch gnome-terminal')

# Open wireshark and sniff from the device
dev2.run_from_namespace('wireshark')

# TCP connections
dev1.run_from_namespace('nc -l 0.0.0.0 8888')
dev2.run_from_namespace('nc 192.168.250.1 8888')

# etc.
```

And for cleanup:

```python
switch.disconnect_device(dev1)
switch.disconnect_device(dev2)

switch.term()
```

### Manipulations(VLAN Hopping) and "Punt-Policies"

A very good example for VLAN-Hopping and Punt-Policies can be seen
in tests/test_manipulation (test_vlan_hopping_and_punt_policies).
