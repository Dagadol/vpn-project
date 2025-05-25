from collections import deque, defaultdict

from scapy.layers.inet import IP, UDP, TCP
import time


class ClassNAT:
    def __init__(self, my_ip, users_amount: int, users=None):
        # if users:  # todo, i should be the one to assign IPs to the virtual adapters

        # set users allowed to connect to this server
        self.users_addr = users  # this is equal to users even if users is None, so self.users_addr will point to users
        if users is None:  # fixme, i dont really like this, because i want users_addr to point at user
            self.users_addr = dict()  # dict of allowed users. {v_addr: (user_ip, user_port)}
        # todo change to defaultdict(int)
        # else:

        self.vpn_private_ip = my_ip
        # Available NAT ports
        # todo try optimize to use sockets and struct instead of scapy
        # fixme port pool get exhausted early think about a new way to deal with it
        # maybe less ports per user or more ports, or limit user port use. D
        users_amount *= 500
        users_amount += 50000
        max_ports = 65535 - 50000
        users_amount = min(users_amount, max_ports // 500)
        self.port_pool = deque(range(50000, 50000 + users_amount * 500))

        self.nat_map = {}  # (client_ip, client_port, proto): {(dst_ip, dst_port), public_port}
        self.rev_map = defaultdict(dict)  # {(public_port, proto): (dst_ip, dst_port), (client_ip, client_port)}

        self.nat_timeouts = {}  # Track last activity time
        self.cleanup = False

    def get_socket_dst(self, data=None, ip: str = "") -> None | tuple[str, int]:
        if ip:
            if ip in self.users_addr:
                return self.users_addr[ip]
            return None
        if data:
            try:
                ip = data[IP].dst
                if ip in self.users_addr:
                    addr = self.users_addr[ip]
                    return addr
                print("VM's ip:", ip)
            except Exception as e:
                print("get_socket_dst: ", e)
        return None

    def udp_recv(self, data: bytes, addr) -> bytes | None:  # called udp because data received through a UDP socket
        """
        Translate data source and save in the NAT table.
        - extract data from udp and change the address to server's
        :param data: requests or data received from client
        :param addr: (IP address, udp source port)
        :return: data to send (with updated source IP and source port)
        """
        # change from bytes to scapy
        packet_data = IP(data)  # must IP because of wireguard
        # check vm IP
        packet_source = packet_data.src
        if packet_source in self.users_addr:

            # check addr validity if vm IP is valid
            if self.users_addr[packet_source] != addr:
                print("spoof attack, from:", addr)
                return None
            try:
                packet_layer4, proto = self.tcp_udp(packet_data)
                if not proto:
                    return None
                info_address = (packet_source, packet_layer4.sport, proto)
            except AttributeError:
                return None

            # Simplify port assignment (remove the for-loop):
            if info_address not in self.nat_map:
                # try assign a used port before pulling new one
                info_dest = (packet_data.dst, packet_layer4.dport)
                public_port = self.port_pool.popleft()  # Always take a new port
                self.nat_map[info_address] = (info_dest, public_port)
                self.rev_map[(public_port, proto)][info_dest] = info_address[:-1]
            else:
                # print("*****"*10, "reusing connection")
                public_port = self.nat_map[info_address][1]
                if len(self.nat_map[info_address]) > 2:
                    print("bad")

            # update port timeout
            self.nat_timeouts[(info_address, public_port)] = time.time()

            # update sources
            packet_data.src = self.vpn_private_ip
            packet_layer4.sport = public_port  # get the public port

            # update checksum
            del packet_layer4.chksum
            del packet_data.chksum

            return bytes(packet_data)

        print("non assigned addr:", addr)
        return None  # invalid address

    def internet_recv(self, scapy_packet: IP) -> tuple[IP, tuple[str, int]] | tuple[None, None]:
        """
        get data in format of scapy, return data with updated destinations
        return address info of the client

        :param scapy_packet: scapy TCP/UDP packet
        :return: data, client's ip address
        """
        scapy_packet = scapy_packet[IP]
        if scapy_packet.dst != self.vpn_private_ip:  # drop packet if destination is not this VPN
            # print("wrong dest")
            return None, None

        # get layer 4 of the packet  (UDP/TCP)
        layer4, proto = self.tcp_udp(scapy_packet)
        if not proto:
            print("invalid internet packet struct:", scapy_packet)
            return None, None

        # vpn public port
        public_port = layer4.dport
        # internet source info
        source_ip = scapy_packet.src  # (client_dest_ip)
        source_port = layer4.sport  # (client_dest_port)
        info_address = (source_ip, source_port)  # (client_dest_addr)

        if (public_port, proto) in self.rev_map.keys():
            if info_address in self.rev_map[(public_port, proto)]:
                # client address info
                addr = self.rev_map[(public_port, proto)][info_address]

                # update port timeout
                self.nat_timeouts[((addr[0], addr[1], proto), public_port)] = time.time()

                # update destinations to client address
                layer4.dport = addr[1]  # client's original port
                scapy_packet.dst = addr[0]

                # update checksum
                del scapy_packet.chksum
                del layer4.chksum
                # data contains not enough info in order to
                # extract variables to match `sendto(data, (-, -))`
                # it is missing ip and port.
                # in order to get these, you can use the function `get_socket_dst` in the server code
                return scapy_packet, self.get_socket_dst(ip=addr[0])

        # print(f"invalid connection: {data}")
        return None, None

    def cleanup_nat_table(self):
        """Remove stale NAT entries"""
        while self.cleanup:
            time.sleep(30)
            now = time.time()

            ports_to_recycle = list(set([(info_addr[2], port) for (info_addr, port) in self.nat_timeouts.keys()]))
            amount_of_active_ports = len(ports_to_recycle)

            stale = deque()
            for (info_addr, port), t in self.nat_timeouts.items():
                if info_addr[2] == "tcp":
                    if now - t > 120:
                        stale.append((info_addr, port))
                    else:
                        if ("tcp", port) in ports_to_recycle:
                            ports_to_recycle.remove(("tcp", port))

                else:  # udp case
                    if now - t >= 30:
                        stale.append((info_addr, port))
                    else:
                        if ("udp", port) in ports_to_recycle:
                            ports_to_recycle.remove(("udp", port))

            for proto, port in ports_to_recycle:
                # Remove all rev_map entries for (port, proto)
                del self.rev_map[(port, proto)]
                # Return the port to the pool if not already there
                if port not in self.port_pool:
                    self.port_pool.append(port)

            for info_addr, port in stale:
                del self.nat_timeouts[(info_addr, port)]
                del self.nat_map[info_addr]
                self.rev_map = defaultdict(dict, {k: {sub_k: sub_v for sub_k, sub_v in v.items() if
                                                      sub_v != info_addr[:-1] or k != (port, info_addr[2])} for k, v in
                                                  self.rev_map.items()})

            cleaned_up = len(stale)
            amount_of_active_ports -= len(ports_to_recycle)
            if cleaned_up:
                print(f"Cleanup: Removed {cleaned_up} entries")
            print(f"connections amount: {len(self.nat_map)}, Entries amount: {amount_of_active_ports}")

    @staticmethod
    def tcp_udp(p):
        """
        get the TCP/UDP layer of the packet.
        :param p: packet in scapy structure
        :return: fourth layer of the packet
        """
        if IP in p:
            if UDP in p:
                return p[UDP], "udp"
            elif TCP in p:
                return p[TCP], "tcp"
        print("problems with the transport layer of the packet")
        try:
            return p[UDP], "udp"
        except IndexError:
            try:
                return p[TCP], "tcp"
            except IndexError:
                print("problematic packet is:", p)
                return None, None


"""
def temp_save(self=None, info_address=None, packet_data=None, packet_layer4=None, proto=None):
    if info_address not in self.nat_map.keys():
        # try assign a used port before pulling new one
        info_dest = (packet_data.dst, packet_layer4.dport)
        public_port = 0
        for (port, temp_proto) in self.rev_map.keys():
            if temp_proto != proto:
                if (port, proto) not in self.rev_map.keys():
                    public_port = port
                    break
            else:
                if info_dest not in self.rev_map[(port, temp_proto)]:
                    public_port = port
                    break

        # pull a new port
        if not public_port:
            public_port = self.port_pool.popleft()

        # append source info address, attach a unique public port, and add destination info
        self.nat_map[info_address] = (info_dest, public_port)
        self.rev_map[(public_port, proto)][info_dest] = info_address[:-1]
"""
