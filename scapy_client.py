import socket
import hashlib
import threading
from scapy.all import sniff, send
from scapy.layers.inet import IP

import connect_protocol
import nat_class


class VPNClient:
    def __init__(self, vpn_server_ip: str, virtual_adapter_ip: str, virtual_adapter_name: str,
                 initial_vpn_port: int, client_port: int, private_ip: str):
        self.vpn_ip = vpn_server_ip
        self.virtual_adapter_ip = virtual_adapter_ip
        self.virtual_adapter_name = virtual_adapter_name
        self.vpn_port = initial_vpn_port  # Will be updated during first connection
        self.my_port = client_port
        self.private_ip = private_ip

        self.active = False
        self.udp_socket = None
        self.key = None
        self.receive_thread = None
        self.sniff_thread = None

    def _first_connection(self) -> bytes | None:
        """Establish initial TCP connection and perform key exchange"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                sock.connect((self.vpn_ip, self.vpn_port))
                break
            except Exception as e:
                print(f"Connection error: {e}")
                continue

        shared_key = connect_protocol.dh_get(sock)
        cmd, data = connect_protocol.get_msg(sock, shared_key)

        if cmd != "f_conn":
            print(f"First connection failed: {cmd} {data}")
            sock.close()
            return None

        # Update with negotiated port from server
        self.vpn_port = int(data)
        sock.close()
        return shared_key

    def open_connection(self):
        """Start VPN connection and begin processing threads"""
        self.key = self._first_connection()
        if not self.key:
            print("Failed to establish initial connection")
            return

        self.active = True
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((self.private_ip, self.my_port))
        self.udp_socket.settimeout(1)  # For cleaner shutdown

        # Start processing threads
        self.sniff_thread = threading.Thread(target=self._receive_from_adapter)
        self.receive_thread = threading.Thread(target=self._receive_from_vpn)

        self.sniff_thread.start()
        self.receive_thread.start()
        print("VPN connection established")

    def end_connection(self):
        """Gracefully shutdown VPN connection"""
        self.active = False
        print("Shutting down VPN connection...")

        if self.udp_socket:
            self.udp_socket.close()

        if self.sniff_thread:
            self.sniff_thread.join()
        if self.receive_thread:
            self.receive_thread.join()

        print("VPN connection terminated")

    def _send_to_vpn(self, pkt):
        """Encrypt and send packet to VPN server"""
        raw_data = bytes(pkt)
        encrypted = connect_protocol.encrypt(raw_data, self.key)
        checksum = hashlib.md5(encrypted).hexdigest()
        self.udp_socket.sendto(
            f"{checksum}~~".encode() + encrypted,
            (self.vpn_ip, self.vpn_port))
        print(f"Sent packet to VPN: {pkt.summary()}")

    def _scapy_filter(self, pkt):
        """Filter for packets from virtual adapter not destined for VPN"""
        if IP in pkt:
            try:
                return (pkt[IP].src == self.virtual_adapter_ip and
                        nat_class.tcp_udp(pkt).dport != self.vpn_port)
            except AttributeError:
                return False
        return False

    def _receive_from_adapter(self):
        """Sniff virtual adapter and forward to VPN"""
        sniff(
            prn=lambda p: self._send_to_vpn(p),
            lfilter=self._scapy_filter,
            iface=self.virtual_adapter_name,
            stop_filter=lambda: not self.active
        )
        print("Stopped sniffing virtual adapter")

    def _receive_from_vpn(self):
        """Receive from VPN server and inject into virtual adapter"""
        while self.active:
            try:
                data, addr = self.udp_socket.recvfrom(65535)
                if addr[0] != self.vpn_ip:
                    continue

                # Split checksum and data
                checksum, _, encrypted = data.partition(b"~~")
                if hashlib.md5(encrypted).hexdigest() != checksum.decode():
                    print("Checksum mismatch!")
                    continue

                decrypted = connect_protocol.decrypt(encrypted, self.key)
                pkt = IP(decrypted)
                send(pkt, verbose=0)
                print(f"Injected packet: {pkt.summary()}")

            except (socket.timeout, ValueError):
                continue
            except Exception as e:
                if self.active:
                    print(f"Receive error: {e}")
                break
        print("Stopped receiving from VPN server")


if __name__ == '__main__':
    # Example usage
    client = VPNClient(
        vpn_server_ip="10.0.0.20",
        virtual_adapter_ip="10.0.0.50",
        virtual_adapter_name="wrgrd",
        initial_vpn_port=5123,
        client_port=8800,
        private_ip="10.0.0.11"
    )

    try:
        client.open_connection()
        # Keep main thread alive while connection is active
        while client.active:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        client.end_connection()
