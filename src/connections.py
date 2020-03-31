import socket
import asyncio
import threading
from scapy.all import Ether
from collections import namedtuple
from contextlib import suppress
import concurrent.futures

from src.util import PortType, add_vlan_tag, fix_checksums, apply_bpf_filter
from src.manipulation import ManipulateArgs, ManipulateActions


DeviceEntry = namedtuple('DeviceEntry', [
    'dev',
    'sock',
    'vlan',
    # Trunk/Access
    'port_type',
])

IP_MAX_SIZE = 65535

MAX_WORKERS = 5
NO_FILTER = None


class Connections(object):

    def __init__(self):
        self._connections_thread = threading.Thread(target=self._start_event_loop)
        self._event_loop = None
        self._devices = list()
        self._message_queue = None
        self._executers = None

        self._manipulate_cb = None
        self._manipulate_filter = NO_FILTER
        self._manipulate_dup = False

    async def _read_message_queue(self):
        while True:
            packet, dev_entry = await self._message_queue.get()
            await self._process_packet(packet, dev_entry)

    async def _process_packet(self, packet, src_device_entry):
        # Should we deal with tagging. We left an option for the manipulator
        # to tag the packet.
        should_inject_raw = False

        packets = [packet]

        if self._manipulate_cb is not None:
            # We'll manipulate if there's no filter or if there's
            # filter and the packet matches the filter
            if self._manipulate_filter == NO_FILTER or \
                    apply_bpf_filter(packet, self._manipulate_filter):

                # In case the packet matches the filter, and `duplicate` is not
                # set, we remove the packet from the list, since the manipulator
                # might drop the packet.
                if not self._manipulate_dup:
                    packets.remove(packet)

                packet, action = await self._event_loop.run_in_executor(
                    self._executers,
                    self._manipulate_cb,
                    ManipulateArgs(packet, src_device_entry.port_type, src_device_entry.vlan))

                if action == ManipulateActions.INJECT_RAW:
                    should_inject_raw = True
                    packets.append(packet)
                elif action == ManipulateActions.HANDLE_ENCAP:
                    should_inject_raw = False
                    packets.append(packet)
                # else - action is DROP, so we don't add the packet to the list.

        for packet in packets:

            src_vlan = self._get_vlan_by_mac(Ether(packet).src)
            if src_vlan is None:
                return None

            # Looking for the destination device
            for dst_device in self._devices:
                if dst_device.dev.get_mac == Ether(packet).dst and dst_device.vlan == src_vlan:

                    if dst_device.port_type == PortType.TRUNK and not should_inject_raw:
                        packet = add_vlan_tag(packet, dst_device.vlan)

                    packet = fix_checksums(packet)
                    await self._event_loop.sock_sendall(dst_device.sock, packet)

    def _read_raw_packet(self, device_entry):
        try:
            packet = device_entry.sock.recv(IP_MAX_SIZE)
            self._message_queue.put_nowait((packet, device_entry))
        except OSError:
            # TODO: Currently the interface is closed successfully, but the cb
            # raises an exception.
            pass

    def _start_event_loop(self):
        self._event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._event_loop)

        self._executers = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)

        self._message_queue = asyncio.Queue()
        asyncio.ensure_future(self._read_message_queue())

        try:
            self._event_loop.run_forever()

            for task in asyncio.Task.all_tasks():
                task.cancel()

                with suppress(asyncio.CancelledError):
                    # await until task is completed if it is currently running/pending.
                    self._event_loop.run_until_complete(task)
        finally:
            self._event_loop.close()

    def _update_arp_tables(self, new_dev):
        for curr_dev in self._devices:
            # If both devices in the same vlan, they should update each other with their addresses.
            if new_dev.vlan == curr_dev.vlan:
                new_dev.dev.run_from_namespace('arp -s {ip} {mac}'.format(
                    ip=curr_dev.dev.get_ip, mac=curr_dev.dev.get_mac))

                curr_dev.dev.run_from_namespace('arp -s {ip} {mac}'.format(
                    ip=new_dev.dev.get_ip, mac=new_dev.dev.get_mac))

    def _get_vlan_by_mac(self, mac):
        for dev_entry in self._devices:
            if mac == dev_entry.dev.get_mac:
                return dev_entry.vlan

        return None

    def append_device(self, dev, vlan, port_type):
        def _append_device_entry(self, new_dev_entry):
            self._devices.append(new_dev_entry)

        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind(('br-{}'.format(dev.get_name), 0))

        new_dev_entry = DeviceEntry(dev, sock, vlan, port_type)

        self._update_arp_tables(new_dev_entry)

        self._event_loop.add_reader(sock, self._read_raw_packet, new_dev_entry)

        # We're pushing the job into the event loop, so no lock is needed.
        # threadsafe since we're calling it from the main thread,
        # and not from the eventloop thread.
        self._event_loop.call_soon_threadsafe(_append_device_entry, self, new_dev_entry)

    def remove_device(self, dev_to_remove):
        def _remove_device_entry(self, dev_to_remove):
            for dev_entry in self._devices:
                if dev_entry.dev == dev_to_remove:
                    dev_entry.sock.close()
                    self._event_loop.remove_reader(dev_entry.sock)
                    self._devices.remove(dev_entry)
                    break

        self._event_loop.call_soon_threadsafe(_remove_device_entry, self, dev_to_remove)

    def set_manipulation(self, cb, bpf_filter, duplicate):
        ''' Assumes cb is in valid form '''
        def __set_manipulation(cb, bpf_filter):
            self._manipulate_cb = cb
            self._manipulate_filter = bpf_filter
            self._manipulate_dup = duplicate

        # set_manipulation is called from the main thread.
        # Since we're affecting the event loop thread, we should call_soon_threadsafe,
        # so the call will be synchronized.
        self._event_loop.call_soon_threadsafe(__set_manipulation, cb, bpf_filter)

    def start_connections_thread(self):
        self._connections_thread.start()

    def stop_connections_thread(self):
        self._event_loop.call_soon_threadsafe(self._event_loop.stop)
