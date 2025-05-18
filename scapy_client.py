import ssl
import socket
import hashlib
import threading
import time

from scapy.config import conf
from scapy.all import sniff
from scapy.arch.windows import get_windows_if_list
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether  # used when injecting the traffic to the physical interface

import gui_master
import connect_protocol
from adapter_conf import get_private_ip, get_physical_private_ip


def tcp_udp(p):
    """
    get the TCP/UDP layer of the packet.
    :param p: packet in scapy structure
    :return: fourth layer of the packet
    """
    if IP in p:
        if UDP in p:
            return p[UDP]
        elif TCP in p:
            return p[TCP]
    print("problems with the transport layer of the packet")
    try:
        return p[UDP]
    except IndexError:
        try:
            return p[TCP]
        except IndexError:
            print("problematic packet is:", p)
            return None


class VPNClient:
    def __init__(self, vpn_server_ip: str, virtual_adapter_ip: str, virtual_adapter_name: str,
                 initial_vpn_port: int, client_port: int, gui: gui_master.AppGUI):
        self.vpn_ip = vpn_server_ip
        self.virtual_adapter_ip = virtual_adapter_ip
        self.virtual_adapter_name = virtual_adapter_name
        self.vpn_port = initial_vpn_port  # Will be updated during first connection
        self.my_port = client_port
        self.private_ip = get_private_ip()  # private_ip
        self.gui = gui

        self.active = False
        self.udp_socket = None
        self.key = None
        self.receive_thread = None
        self.sniff_thread = None

    def _first_connection(self, server_code: str, my_password1: str, my_password2: str) -> bytes | None:
        """Establish initial TCP connection and perform key exchange"""
        def password_exchange():
            """password handshake: client side"""
            command, hash_received = connect_protocol.get_msg(sock)
            if command != "exchange" or hash_received != hashlib.sha256(my_password1.encode()).hexdigest():
                print("WARNING: MITM attack suspicion")
                return False
            sock.send(connect_protocol.create_msg(hashlib.sha256(server_code.encode()).hexdigest(), "exchange"))
            command, second_hash_received = connect_protocol.get_msg(sock)
            if command != "exchange" or second_hash_received != hashlib.sha256(my_password2.encode()).hexdigest():
                return False
            return True

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"my ip: '{self.private_ip}' to port: {self.vpn_port}")
        # my_sock.bind((self.private_ip, self.vpn_port))
        # my_sock.listen(1)
        while True:
            try:
                sock.connect((self.vpn_ip, self.vpn_port))
                try:
                    status = password_exchange()
                    if not status:
                        sock.close()
                        return False
                except Exception as e:
                    print(f"WARNING {e}")
                    sock.close()
                    return False
                # sock, addr = my_sock.accept()
                # if addr[0] != self.vpn_ip:
                #     sock.close()
                #     continue
                break
            except KeyboardInterrupt:
                print("key board interrupt during key exchange")
                self.gui.logger.error("key board interrupt during key exchange")
                self.end_connection()
                return None
            except WindowsError as e:
                print(f"Connection error: {e}")
                self.gui.logger.warning(f"Connection error: {e}")
                continue
            except Exception as e:
                print(f"Error at key exchange: {e}")
                return None
            except BaseException as e:
                print(f"base exception {e}")

        shared_key = connect_protocol.dh_get(sock)
        cmd, data = connect_protocol.get_msg(sock, shared_key)

        if cmd != "f_conn":
            print(f"First connection failed: {cmd} {data}")
            self.gui.logger.error(f"First connection failed: {cmd} {data}")
            sock.close()
            return None

        # Update with negotiated port from server
        self.vpn_port = int(data)

        # check if using ZeroTier
        # IPs wouldn't match in case of ZeroTier is in use
        # self.private_ip is zerotier then the physical_
        temp_private_ip = get_physical_private_ip()
        if self.private_ip != temp_private_ip:
            data = f"true~{temp_private_ip}"  # uses ZeroTier
        else:
            data = f"false~{temp_private_ip}"  # Doesn't use ZeroTier
        # in both cases the VPN server needs the client's private IP
        # because to verify the packets
        sock.send(connect_protocol.create_msg(data, "f_conn", key=shared_key))

        sock.close()
        return shared_key

    def open_connection(self, server_code, my_password1, my_password2):
        """Start VPN connection and begin processing threads"""
        self.active = True
        self.key = self._first_connection(server_code, my_password1, my_password2)
        if not self.key:
            print("Failed to establish initial connection")
            self.gui.logger.error("Failed to establish initial connection")
            return False

        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((self.private_ip, self.my_port))
        self.udp_socket.settimeout(1)  # For cleaner shutdown

        # Start processing threads
        self.sniff_thread = threading.Thread(target=self._receive_from_adapter)
        self.receive_thread = threading.Thread(target=self._receive_from_vpn)

        self.sniff_thread.start()
        self.receive_thread.start()
        print("VPN connection established")
        self.gui.logger.debug("VPN connection established")
        return True

    def end_connection(self):
        """Gracefully shutdown VPN connection"""
        self.active = False
        print("Shutting down VPN connection...")
        # self.gui.logger.debug("Shutting down VPN connection...")

        if self.udp_socket:
            self.udp_socket.close()

        if self.sniff_thread:
            self.sniff_thread.join(timeout=5)
        if self.receive_thread:
            self.receive_thread.join(timeout=5)

        print("VPN connection terminated")
        # self.gui.logger.debug("VPN connection terminated")

    def _send_to_vpn(self, pkt):
        """Encrypt and send packet to VPN server"""
        self.gui.logger.info(str(pkt) + "pkt_log")  # Log the packet

        raw_data = bytes(pkt)
        encrypted = connect_protocol.encrypt(raw_data, self.key)
        checksum = hashlib.md5(encrypted).hexdigest()
        self.udp_socket.sendto(
            f"{checksum}~~~".encode() + encrypted,
            (self.vpn_ip, self.vpn_port))
        # print(f"Sent packet to VPN: {pkt.summary()}")

    def _scapy_filter(self, pkt):
        """Filter for packets from virtual adapter not destined for VPN"""
        if IP in pkt:
            try:
                return (pkt.src == self.virtual_adapter_ip and
                        tcp_udp(pkt).dport != self.vpn_port)
            except AttributeError:
                return False
        return False

    def _receive_from_adapter(self):
        """Sniff packets from the virtual adapter and forward them to the VPN."""
        conf.ifaces.reload()
        time.sleep(2)  # After reloading interfaces

        attempt = 0
        while self.active:  # Continue as long as the VPN connection is active
            try:
                sniff(
                    prn=lambda p: self._send_to_vpn(p),  # Function to process packets
                    filter="ip",
                    lfilter=self._scapy_filter,  # Packet filter, if any
                    iface=self.virtual_adapter_name,  # Interface name (e.g., "wrgrd")
                    stop_filter=lambda p: not self.active  # Stop when connection ends
                )
                # print("Successfully started sniffing on the virtual adapter.")
                break  # Exit the loop once sniffing starts successfully
            except Exception as e:
                attempt += 1

                # every 5 failed attempts, change name of the iface
                if attempt % 5 == 0:
                    conf.ifaces.reload()

                print(f"Attempt {attempt}, with the name '{self.virtual_adapter_name}': Failed to start sniffing - {e}")
                time.sleep(1)  # Wait 1 second before retrying
        else:
            print("Stopped sniffing due to VPN connection termination.")

    def _receive_from_vpn(self):
        """Receive from VPN server and inject into virtual adapter"""
        print("started VPN receiving")
        i = 1
        conf.ifaces.reload()
        time.sleep(2)

        # ip = get_physical_private_ip()
        ip = "127.0.0.1"
        # mac = [iface["mac"] for iface in get_windows_if_list() if ip in iface.get("ips", [])][0]
        iface = [iface["description"] for iface in get_windows_if_list() if ip in iface.get("ips", [])][0]
        print(f"iface: {iface}")
        try:
            scapy_socket = conf.L3socket(iface=iface)
        except OSError:
            print("failed to connect to iface by iface description; trying by loopback_name")
            scapy_socket = conf.L3socket(iface=conf.loopback_name)
        while self.active:
            i += 1
            try:
                data, addr = self.udp_socket.recvfrom(65535)
                # print("received data")
                if addr[0] != self.vpn_ip:
                    continue

                # Split checksum and data
                checksum, _, encrypted = data.partition(b"~~~")
                if hashlib.md5(encrypted).hexdigest() != checksum.decode():
                    # print("Checksum mismatch!")
                    continue

                decrypted = connect_protocol.decrypt(encrypted, self.key)
                # pkt = Ether(dst=mac) / IP(decrypted)
                # del pkt[IP].chksum
                pkt = IP(decrypted)

                scapy_socket.send(pkt)
                self.gui.logger.info(str(pkt) + "pkt_log")  # Log the packet

            except (socket.timeout, ValueError):
                continue
            except Exception as e:
                if self.active:
                    print(f"Receive error: {e}")
                    if i == 10:
                        # from scapy.config import conf
                        conf.ifaces.reload()
                        time.sleep(3)
                else:
                    break
        print("Stopped receiving from VPN server")
        self.gui.logger.debug("Stopped receiving from VPN server")


if __name__ == '__main__':
    import adapter_conf
    import gui_master

    test_gui = gui_master.AppGUI()
    test_gui.main()

    v_interface = adapter_conf.Adapter(ip="10.2.0.1", vpn_ip="172.29.149.44")
    #print("name:", f"'{v_interface.name}'", "\tip:", v_interface.ip, "\nwait 15 seconds")
    #print("wait 25")
    #time.sleep(10)
    #print("time is over")
    test_gui.main()
    # Example usage
    client = VPNClient(  # won't work, because GUI is needed as a parameter
        vpn_server_ip="172.29.149.44",
        #virtual_adapter_ip="10.0.0.50",
        virtual_adapter_ip=v_interface.ip,
        #virtual_adapter_name="wrgrd",
        virtual_adapter_name=v_interface.name,
        initial_vpn_port=52001,
        client_port=8800,
        private_ip="172.29.168.164",
        gui=test_gui
    )

    client.open_connection()
    test_gui.mainloop()
    # try:
    #     # Keep main thread alive while connection is active
    #     while client.active:
    #         threading.Event().wait(1)
    # except KeyboardInterrupt:
    client.end_connection()
    v_interface.delete_adapter()
