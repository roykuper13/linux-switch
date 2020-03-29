import threading
from scapy.all import Ether, IP, Raw

from src.device import Device
from src.manipulation import ManipulateArgs, ManipulateRet


D1_ADDR = '192.168.250.1'
D2_ADDR = '192.168.250.2'
D3_ADDR = '192.168.1.1'
D4_ADDR = '192.168.1.2'

GLOBAL_D3_MAC = None
GLOBAL_D4_MAC = None


def forward_d1_to_d3(arg: ManipulateArgs) -> ManipulateRet:
    '''
    Replace addresses of d2 with d4, so the packet will be hopped
    to the second vlan
    '''
    global GLOBAL_D3_MAC
    global GLOBAL_D4_MAC
    packet = Ether(arg.packet)

    if not (IP in packet and packet[IP].dst == D2_ADDR and packet[IP].src == D1_ADDR):
        return ManipulateRet(arg.packet, False)

    packet[IP].src = D4_ADDR
    packet[IP].dst = D3_ADDR

    packet[Ether].src = GLOBAL_D4_MAC
    packet[Ether].dst = GLOBAL_D3_MAC

    return ManipulateRet(Raw(packet).load, False)


def test_vlan_hopping(switch):
    '''
    In this test, d1 is in vlan 20, and it'll try to connect
    to d3, which is part of vlan 10. The manipulation callback works follow:
    For each packet that its source is d1 and destined to d2,
    the callback will change the packet so it'll look like the source is d4,
    and it's destined to d3. The switch will think that the packet came from
    d4 who's part of vlan 10, so it'll forward the packet to d3 (who's also in vlan 10).
    That is an example of a VLAN hopping.
    '''
    global GLOBAL_D3_MAC
    global GLOBAL_D4_MAC

    d1 = Device('a', D1_ADDR, '255.255.255.0')
    d2 = Device('b', D2_ADDR, '255.255.255.0')

    d3 = Device('c', D3_ADDR, '255.255.255.0')
    d4 = Device('d', D4_ADDR, '255.255.255.0')

    assert switch.connect_device_trunk(d1, 20)
    assert switch.connect_device_access(d2, 20)

    assert switch.connect_device_trunk(d3, 10)
    assert switch.connect_device_access(d4, 10)

    GLOBAL_D3_MAC = d3.get_mac
    GLOBAL_D4_MAC = d4.get_mac

    switch.set_manipulation(forward_d1_to_d3)

    def _run_listening_nc(dev):
        out = dev.run_from_namespace('timeout 5s nc -lu 0.0.0.0 4444')
        assert 'hello' == out

    t = threading.Thread(target=_run_listening_nc, args=(d3, ))
    t.start()

    out = d1.run_from_namespace('bash -c "echo hello | nc -u 192.168.250.2 4444 -w 3"')
    assert '' == out

    switch.disconnect_device(d1)
    switch.disconnect_device(d2)
    switch.disconnect_device(d3)
    switch.disconnect_device(d4)
