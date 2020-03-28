import threading

from src.device import Device


def test_access_connection(switch):
    d1 = Device('a', '192.168.250.1', '255.255.255.0')
    d2 = Device('b', '192.168.250.2', '255.255.255.0')

    switch.connect_device_access(d1, 20)
    switch.connect_device_access(d2, 20)

    out = d1.run_from_namespace('ping -c 1 192.168.250.2')
    assert '1 packets transmitted, 1 received' in out

    out = d2.run_from_namespace('ping -c 1 192.168.250.1')
    assert '1 packets transmitted, 1 received' in out

    switch.disconnect_device(d1)
    switch.disconnect_device(d2)


def test_trunk_connection(switch):
    d1 = Device('a', '192.168.250.1', '255.255.255.0')
    d2 = Device('b', '192.168.250.2', '255.255.255.0')

    switch.connect_device_trunk(d1, 20)
    switch.connect_device_trunk(d2, 20)

    out = d1.run_from_namespace('ping -c 1 192.168.250.2')
    assert '1 packets transmitted, 1 received' in out

    out = d2.run_from_namespace('ping -c 1 192.168.250.1')
    assert '1 packets transmitted, 1 received' in out

    switch.disconnect_device(d1)
    switch.disconnect_device(d2)


def test_different_port_type_connection(switch):
    d1 = Device('a', '192.168.250.1', '255.255.255.0')
    d2 = Device('b', '192.168.250.2', '255.255.255.0')

    switch.connect_device_trunk(d1, 20)
    switch.connect_device_access(d2, 20)

    out = d1.run_from_namespace('ping -c 1 192.168.250.2')
    assert '1 packets transmitted, 1 received' in out

    out = d2.run_from_namespace('ping -c 1 192.168.250.1')
    assert '1 packets transmitted, 1 received' in out

    switch.disconnect_device(d1)
    switch.disconnect_device(d2)


def test_vlans(switch):
    d1 = Device('a', '192.168.250.1', '255.255.255.0')
    d2 = Device('b', '192.168.250.2', '255.255.255.0')
    d3 = Device('c', '192.168.250.3', '255.255.255.0')

    switch.connect_device_trunk(d1, 20)
    switch.connect_device_access(d2, 20)

    # Note that d3 is in a different vlan
    switch.connect_device_access(d3, 10)

    out = d1.run_from_namespace('ping -c 1 192.168.250.2')
    assert '1 packets transmitted, 1 received' in out

    out = d2.run_from_namespace('ping -c 1 192.168.250.1')
    assert '1 packets transmitted, 1 received' in out

    # The following should fail as d3 is in a different vlan
    out = d3.run_from_namespace('ping -c 1 -W 2 192.168.250.1')
    assert '1 packets transmitted, 0 received' in out

    out = d3.run_from_namespace('ping -c 1 -W 2 192.168.250.2')
    assert '1 packets transmitted, 0 received' in out

    switch.disconnect_device(d1)
    switch.disconnect_device(d2)
    switch.disconnect_device(d3)


def test_tcp_connection(switch):
    d1 = Device('a', '192.168.250.1', '255.255.255.0')
    d2 = Device('b', '192.168.250.2', '255.255.255.0')

    switch.connect_device_trunk(d1, 20)
    switch.connect_device_trunk(d2, 20)

    def _run_listening_nc(dev):
        out = dev.run_from_namespace('timeout 5s nc -l 0.0.0.0 4444')
        assert 'hello' == out

    t = threading.Thread(target=_run_listening_nc, args=(d1, ))
    t.start()

    out = d2.run_from_namespace('bash -c "echo hello | nc 192.168.250.1 4444 -w 3"')
    assert '' == out

    switch.disconnect_device(d1)
    switch.disconnect_device(d2)


def test_udp_connection(switch):
    d1 = Device('a', '192.168.250.1', '255.255.255.0')
    d2 = Device('b', '192.168.250.2', '255.255.255.0')

    switch.connect_device_trunk(d1, 20)
    switch.connect_device_access(d2, 20)

    def _run_listening_nc(dev):
        out = dev.run_from_namespace('timeout 7s nc -lu 0.0.0.0 4444')
        assert 'hello' == out

    t = threading.Thread(target=_run_listening_nc, args=(d1, ))
    t.start()

    out = d2.run_from_namespace('bash -c "echo hello | nc -u 192.168.250.1 4444 -w 5"')
    t.join()

    assert '' == out

    switch.disconnect_device(d1)
    switch.disconnect_device(d2)
