from collections import deque, defaultdict
import time
import socket
import struct


class ClassNAT:
    def __init__(self, my_ip, max_user_conn=1000):
        self.vpn_ip = my_ip
        self.port_pool = deque(range(32768, 60999))  # Expanded port range
        self.nat_table = {}  # Format: {(src_ip, src_port, proto, dst_ip, dst_port): (public_port, last_active)}
        self.user_conn_count = defaultdict(int)  # Track connections per user
        self.max_user_conn = max_user_conn

    def udp_recv(self, data: bytes, client_addr: tuple) -> bytes | None:
        """Process incoming UDP packet from client"""
        # Parse inner IP packet (assuming data = encapsulated IP packet)
        try:
            inner_ip = data[:20]
            src_ip = socket.inet_ntoa(inner_ip[12:16])
            dst_ip = socket.inet_ntoa(inner_ip[16:20])
            proto = inner_ip[9]
            src_port, dst_port = self._parse_transport_header(data[20:], proto)
        except Exception as e:
            print(f"Failed to parse packet: {e}")
            return None

        # Validate client
        if client_addr[0] != src_ip:
            print(f"Spoof attempt: {client_addr[0]} != {src_ip}")
            return None

        # Check per-user connection limit
        if self.user_conn_count[src_ip] >= self.max_user_conn:
            print(f"Blocked {src_ip}: connection limit reached")
            return None

        # Create 5-tuple key
        key = (src_ip, src_port, proto, dst_ip, dst_port)

        # Get or assign NAT port
        if key in self.nat_table:
            public_port, _ = self.nat_table[key]
            self.nat_table[key] = (public_port, time.time())  # Update timestamp
        else:
            if not self.port_pool:
                print("NAT port exhaustion!")
                return None
            public_port = self.port_pool.popleft()
            self.nat_table[key] = (public_port, time.time())
            self.user_conn_count[src_ip] += 1

        # Rewrite IP/port headers
        new_packet = self._rewrite_packet(data, src_ip, src_port, public_port)
        return new_packet

    def internet_recv(self, data: bytes) -> tuple[bytes, tuple] | None:
        """Process incoming internet packet"""
        # Parse headers
        try:
            dst_ip = socket.inet_ntoa(data[16:20])
            dst_port = struct.unpack('!H', data[22:24])[0]
            proto = data[9]
        except Exception as e:
            print(f"Invalid packet: {e}")
            return None

        # Find original client using NAT port
        key = next((k for k, v in self.nat_table.items() if v[0] == dst_port), None)
        if not key:
            return None

        src_ip, src_port, _, dst_ip, dst_port = key
        self.nat_table[key] = (dst_port, time.time())  # Update timestamp

        # Rewrite packet for client
        new_packet = self._rewrite_packet(data, dst_ip, dst_port, src_port)
        return new_packet, (src_ip, src_port)

    def _parse_transport_header(self, data: bytes, proto: int) -> tuple[int, int]:
        """Extract src/dst ports from transport header"""
        if proto == 6:  # TCP
            src_port, dst_port = struct.unpack('!HH', data[:4])
        elif proto == 17:  # UDP
            src_port, dst_port = struct.unpack('!HH', data[:4])
        else:
            raise ValueError(f"Unsupported protocol {proto}")
        return src_port, dst_port

    def _rewrite_packet(self, data: bytes, old_ip: str, old_port: int, new_port: int) -> bytes:
        """Rewrite IP/port and update checksums"""
        # Rewrite IP header (source/dest IP)
        new_ip_header = bytearray(data[:20])
        new_ip_header[12:16] = socket.inet_aton(self.vpn_ip)  # Set source IP

        # Rewrite transport header port
        new_transport = bytearray(data[20:])
        new_transport[0:2] = struct.pack('!H', new_port)

        # Recalculate checksums (implement manual calculation here)
        full_packet = bytes(new_ip_header) + bytes(new_transport)
        return full_packet

    def cleanup_nat_table(self):
        """Remove stale entries (TCP: 60s, UDP: 30s)"""
        while True:
            time.sleep(30)
            now = time.time()
            to_delete = []
            for key, (port, last_active) in self.nat_table.items():
                proto = key[2]
                timeout = 60 if proto == 6 else 30
                if now - last_active > timeout:
                    to_delete.append(key)

            for key in to_delete:
                port = self.nat_table[key][0]
                self.port_pool.append(port)
                del self.nat_table[key]
                self.user_conn_count[key[0]] -= 1