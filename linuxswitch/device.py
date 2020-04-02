from linuxswitch.util import shell_run_and_check, convert_subnetmask_to_cidr, run_shell_cmd
from linuxswitch.exception import LongInterfaceException, NamespaceCreationException


class Device(object):

    # IFNAMSIZ is 15 (excluding the null terminator).
    # We're appending at most 8 bytes to the given interface name, so 7
    # characters are left for the user.
    # Note that we prefer to limit the user's input, instead of generating
    # names by ourselves, as the user should know which resources this program
    # is creating (for example, the user might manually delete interfaces
    # by himself).
    INTERFACE_NAME_MAX_SIZE = 7

    netns_commands = [
        # Create veth pair
        'ip link add veth-{name} type veth peer name br-veth-{name}',
        'ip link set br-veth-{name} up',
        # Set the new network namespace's veth interface
        'ip link set veth-{name} netns {name}',
        'ip netns exec {name} ip link set veth-{name} up',
    ]

    def __init__(self, name, ip, subnet_mask):
        if len(name) > self.INTERFACE_NAME_MAX_SIZE:
            raise LongInterfaceException(
                "Device name length must be at most {} characters({})".format(
                    self.INTERFACE_NAME_MAX_SIZE, name))

        # Create the network namespace for the device
        if not shell_run_and_check('ip netns add {}'.format(name)):
            raise NamespaceCreationException(
                "Can not create network namespace '{}' "
                "(Make sure to run the script with root priviliages)".format(name))

        self._dev_name = name
        self._ip = ip
        self._cidr = convert_subnetmask_to_cidr(subnet_mask)
        self._mac = None

        self._ns_is_set = False

    def _get_ns_veth_mac(self):
        """
        In case the veth interface of the new namespace is set (setup_namespace),
        The function returns the mac address of the veth interface (in utf-8).
        Otherwise, the function returns None.
        """
        mac, err = run_shell_cmd(
            'ip netns exec {ns} cat /sys/class/net/veth-{ns}/address'.format(ns=self._dev_name))

        return mac.decode('utf-8') if err == b'' else None

    @property
    def get_name(self):
        return self._dev_name

    @property
    def get_ip(self):
        return self._ip

    @property
    def get_cidr(self):
        return self._cidr

    @property
    def get_mac(self):
        if self._mac is None:
            self._mac = self._get_ns_veth_mac()

        return self._mac

    def get_switch_veth_name(self):
        # This class creates veth pair. One veth is set to the new network namespace
        # in `setup_namespace`. The second veth should be used by the default namespace,
        # later on (See switch.py). Therefore, the default namespace should be able
        # to get the second veth's name.
        return 'br-veth-{}'.format(self._dev_name)

    def get_device_veth_name(self):
        # That is the veth interface in the "device" side (i.e - in the new network
        # namespace side).
        return 'veth-{}'.format(self._dev_name)

    def run_from_namespace(self, cmd):
        """
        Runs a shell command from the device's context (i.e - from
        the network namespace that associated to the device).

        :param cmd: the shell command to execute

        :return str: The result of the command (stdout/stderr)
        """
        out, err = run_shell_cmd('ip netns exec {ns} {cmd}'.format(ns=self._dev_name, cmd=cmd))
        return out.decode('utf-8') if err == b'' else err.decode('utf-8')

    def setup_namespace(self):
        """
        Sets up the network namespace of the device.

        :note: The `Switch` will call this when the device will be connected to it
               (using `connect_device_*`), but it is safe to call this more then once.
        """
        if self._ns_is_set:
            return True

        if not shell_run_and_check(' && '.join(self.netns_commands).format(name=self._dev_name)):
            return False

        self._ns_is_set = True
        return True

    def term(self):
        """
        Cleans the device's network namespace, and the created veth interfaces.

        :note: The `Switch` will call this when the device will be disconnected from it
               (using `disconnect_device`), but it is safe to call this more then once.
        """
        if self._ns_is_set:
            shell_run_and_check('ip netns del {}'.format(self._dev_name))
            # We've created the switch's veth interface, so we are responsible for
            # deleting it.
            shell_run_and_check('ip link del {}'.format(self.get_switch_veth_name()))

            self._ns_is_set = False
