from src.connections import Connections, NO_FILTER
from src.util import shell_run_and_check, PortType
from src.manipulation import validate_manipulation_cb
from src.exception import (NamespaceCreationException,
                           BridgeInterfaceCreationException, NamespaceConnectionException)


class Switch(object):

    def __init__(self):
        self._connections = Connections()
        self._connections.start_connections_thread()

    def _set_bridge_interface(self, dev):
        set_bridge_cmds = [
            'ip link add name {br} type bridge',
            'ip link set {br} up',
            'ip link set {br} promisc on',
            'ip link set {veth} master {br}',
        ]

        return shell_run_and_check(' && '.join(set_bridge_cmds).format(
            br='br-{}'.format(dev.get_name), veth=dev.get_switch_veth_name()))

    def _set_access_connection(self, dev):
        # Set IP to veth interface (within the device's network namespace)
        if not shell_run_and_check(
            'ip netns exec {name} ip addr add {ip}/{cidr} dev veth-{name}'.format(
                name=dev.get_name, ip=dev.get_ip, cidr=dev.get_cidr)):
            return False

        return True

    def _set_trunk_connection(self, dev, vlan):
        vlan_interface_cmds = [
            'ip link add link {iface} name {iface}.v type vlan id {vlan}',
            'ip addr add {ip}/{cidr} brd + dev {iface}.v',
            'ip link set {iface}.v up',
        ]

        # Configure vlan interface inside the network namespace
        concat_cmds = ' && '.join(
            ['ip netns exec {} '.format(dev.get_name) + cmd for cmd in vlan_interface_cmds]).format(
            iface=dev.get_device_veth_name(),
            ip=dev.get_ip,
            cidr=dev.get_cidr,
            vlan=vlan)

        if not shell_run_and_check(concat_cmds):
            return False

        return True

    def connect_device_access(self, dev, vlan):
        if not dev.setup_namespace():
            raise NamespaceCreationException("failed to create network namespace for {}".format(
                dev.get_name))

        if not self._set_bridge_interface(dev):
            raise BridgeInterfaceCreationException(
                "failed to create bridge interface for {}".format(dev.get_name))

        if not self._set_access_connection(dev):
            raise NamespaceConnectionException("failed to create connection to namespace {}".format(
                dev.get_name))

        self._connections.append_device(dev, vlan, PortType.ACCESS)

    def connect_device_trunk(self, dev, vlan):
        if not dev.setup_namespace():
            raise NamespaceCreationException("failed to create network namespace for {}".format(
                dev.get_name))

        if not self._set_bridge_interface(dev):
            raise BridgeInterfaceCreationException(
                "failed to create bridge interface for {}".format(dev.get_name))

        if not self._set_trunk_connection(dev, vlan):
            raise NamespaceConnectionException("failed to create connection to namespace {}".format(
                dev.get_name))

        self._connections.append_device(dev, vlan, PortType.TRUNK)

    def disconnect_device(self, dev):
        # Delete switch's bridge interface
        shell_run_and_check('ip link del br-{}'.format(dev.get_name))

        self._connections.remove_device(dev)

        dev.term()

    def set_manipulation(self, cb, bpf_filter=NO_FILTER):
        if validate_manipulation_cb(cb):
            self._connections.set_manipulation(cb, bpf_filter)
            return True

        return False

    def term(self):
        self._connections.stop_connections_thread()
