import os
import enum
import subprocess
from netaddr import IPAddress
from scapy.all import NoPayload, Ether, Dot1Q, Raw, IP, TCP, UDP, sniff


DOT1Q_ETH_TYPE = 0x8100


class PortType(enum.Enum):
    ACCESS = 0
    TRUNK = 1


def shell_run_and_check(cmd):
    # Pretty ugly but whatever
    res = (b'', b'') == run_shell_cmd(cmd)
    return res


def run_shell_cmd(cmd):
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, stderr = process.communicate()
        return stdout.strip(), stderr.strip()
    except subprocess.CalledProcessError:
        return None, None


def convert_subnetmask_to_cidr(subnet_mask):
    return IPAddress(subnet_mask).netmask_bits()


def add_vlan_tag(packet, vlan):
    packet = Ether(packet)
    layer = packet.firstlayer()

    while not isinstance(layer, NoPayload):
        if 'chksum' in layer.default_fields:
            del layer.chksum

        if (type(layer) is Ether):
            layer.type = DOT1Q_ETH_TYPE

            dot1q = Dot1Q(vlan=vlan)
            dot1q.add_payload(layer.payload)

            layer.remove_payload()
            layer.add_payload(dot1q)
            layer = dot1q

        # advance to the next layer
        layer = layer.payload

    return Raw(packet).load


def fix_checksums(packet):
    packet = Ether(packet)

    if IP in packet:
        del packet[IP].chksum

    if TCP in packet:
        del packet[TCP].chksum

    if UDP in packet:
        del packet[UDP].chksum

    packet = packet.__class__(bytes(packet))
    return Raw(packet).load


def apply_bpf_filter(packet, filter):
    # TODO: this is horrible. Unfortunately scapy's `sniff` (which uses tcpdump)
    # always outputs annoying stuff to stderr, so we have to redirect it to /dev/null.
    # For now we'll settle with this, until this issue will be fixed in scapy.
    stderr_backup = os.dup(2)

    dev_null = os.open('/dev/null', os.O_WRONLY)
    os.dup2(dev_null, 2)

    filtered = len(sniff(offline=Ether(packet), filter=filter).res) == 1

    os.dup2(stderr_backup, 2)
    return filtered
