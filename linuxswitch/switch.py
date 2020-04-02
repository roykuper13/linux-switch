from linuxswitch.connections import Connections, NO_FILTER
from linuxswitch.util import shell_run_and_check, PortType
from linuxswitch.manipulation import validate_manipulation_cb
from linuxswitch.exception import (NamespaceCreationException,
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

    def set_manipulation(self, cb, punt_policies_bpf=NO_FILTER, duplicate=False):
        """
        Sets the manipulation routine.

        Before the switch checks to which device a packet should be forwarded,
        it sends the packet the a manipulation routine.
        You can pass a callback that manipulate the packet, for example, change the
        destination and source addresses and the vlan tag, in order to perform VLAN-Hopping,
        or NAT.

        In addition, In case you want to emulate "Punt-Policies" (decide what packets
        should be forwarded to the manipulation callback), you can pass a bpf filter.
        As mentioned, only packets that are filtered by this bpf filter will be forwarded
        to the manipultion routine before they get processed by the switch.

        :param cb: A callback the the manipulation routine.
                   The callback must have arguments and return annotations,
                   since this function validates this callback using them.

                   A valid callback has to match the following form:
                   1. Recieve one argument. Its type is ManipulateArgs.
                   2. Return ManipulateRet.

                   An example of a valid callback (taken from manipulation.py:
                   `default_manipulation_cb`):

                def default_manipulation_cb(manipulate_args: ManipulateArgs) -> ManipulateRet:
                    return ManipulateRet(manipulate_args.packet, ManipulateActions.HANDLE_ENCAP)

                    This callback for example, just returns the packet.

        :param punt_policies_bpf: The "Punt-Policies". Default is no-filter.
        :param duplicate: True if the packet should be processed by both switch
                          and manipulator, False if the packet should be processed
                          by the manipulator only.
        :return: True if the callback is in a valid form, False otherwise.
        """
        if validate_manipulation_cb(cb):
            self._connections.set_manipulation(cb, punt_policies_bpf, duplicate)
            return True

        return False

    def connect_device_access(self, dev, vlan):
        """
        Connects device to switch in access mode (meaning - both device and switch
        will send untagged packets. Note that the switch will still make sure
        that packets from one vlan will not be forwarded to other vlans).

        :param dev: A `Device` instance that should be connected to the switch.
        :param vlan: The vlan that the device will be associated to.
        """
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
        """
        Connects device to switch in trunk mode (meaning - a vlan interface
        will be created for both switch and device. Both will send and recieve tagged
        packets, with dot1q layer).

        :param dev: A `Device` instance that should be connected to the switch.
        :param vlan: The vlan that the device will be associated to.
        """
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
        """
        Disconnects a device from switch.
        All interfaces and namespaces that were created will be cleaned up.

        :param dev: The `Device` instance to disconnect from the switch.
        """

        # Delete switch's bridge interface
        shell_run_and_check('ip link del br-{}'.format(dev.get_name))

        self._connections.remove_device(dev)

        dev.term()

    def term(self):
        """
        Terminates all connections, and cleans up all left-over namespaces and interfaces.
        """
        self._connections.stop_connections_thread()
