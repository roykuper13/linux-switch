import threading
from scapy.all import Ether, IP, ICMP, Raw

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
    to the second vlan.
    '''
    global GLOBAL_D3_MAC
    global GLOBAL_D4_MAC
    packet = Ether(arg.packet)

    packet[IP].src = D4_ADDR
    packet[IP].dst = D3_ADDR

    packet[Ether].src = GLOBAL_D4_MAC
    packet[Ether].dst = GLOBAL_D3_MAC

    return ManipulateRet(Raw(packet).load, False)


def test_vlan_hopping_and_punt_policies(switch):
    """
    In this test, d1 is in vlan 20, and it'll try to connect
    to d3, which is part of vlan 10. The manipulation callback works follow:
    For each packet that its source is d1 and destined to d2,
    the callback will change the packet so it'll look like the source is d4,
    and it's destined to d3. The switch will think that the packet came from
    d4 who's part of vlan 10, so it'll forward the packet to d3 (who's also in vlan 10).
    That is an example of a VLAN hopping.

    This test also shows the behaviour of the "punt-policies":
    Only packets from d1 to d2 will be passed to the manipulation callback.
    """
    global GLOBAL_D3_MAC
    global GLOBAL_D4_MAC

    d1 = Device('a', D1_ADDR, '255.255.255.0')
    d2 = Device('b', D2_ADDR, '255.255.255.0')

    d3 = Device('c', D3_ADDR, '255.255.255.0')
    d4 = Device('d', D4_ADDR, '255.255.255.0')

    switch.connect_device_trunk(d1, 20)
    switch.connect_device_access(d2, 20)

    switch.connect_device_trunk(d3, 10)
    switch.connect_device_access(d4, 10)

    GLOBAL_D3_MAC = d3.get_mac
    GLOBAL_D4_MAC = d4.get_mac

    # Setting the manipulation routine, and punt-policies
    switch.set_manipulation(forward_d1_to_d3, 'src host {} && dst host {}'.format(
        D1_ADDR, D2_ADDR))

    def _run_listening_nc(dev):
        out = dev.run_from_namespace('timeout 7s nc -lu 0.0.0.0 4444')
        assert 'hello' == out

    # d3 is going to listen
    t = threading.Thread(target=_run_listening_nc, args=(d3, ))
    t.start()

    # and d1 will connect to it
    out = d1.run_from_namespace('bash -c "echo hello | nc -u 192.168.250.2 4444 -w 5"')
    assert '' == out

    # Note that the manipulation callback modifies every packet that it recieves,
    # But it won't recieve this packet (and its reply) since they won't match the
    # bpf filter that we set before. That's why we expect an echo-reply.
    out = d3.run_from_namespace('ping -c 1 192.168.1.2')
    assert '1 packets transmitted, 1 received' in out

    switch.disconnect_device(d1)
    switch.disconnect_device(d2)
    switch.disconnect_device(d3)
    switch.disconnect_device(d4)
