from collections import deque

from scapy.layers.inet import IP, UDP, TCP
import time


def update_checksum(bad_bytes: bytes) -> bytes:  # update checksum using scapy. maybe try with struct later
    # turn bytes to scapy structured
    scapy_struct = IP(bad_bytes)

    # easily remove the IP header's and transport layer header's checksum
    del scapy_struct[IP].chksum
    del tcp_udp(scapy_struct).chksum

    # return bytes (scapy automatically update the checksum with `bytes()`)
    return bytes(scapy_struct)


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


class ClassNAT:
    def __init__(self, users, my_ip):
        if users:  # todo, i should be the one to assign IPs to the virtual adapters
            self.users_addr = users  # users allowed to connect to this server
        else:
            self.users_addr = dict()  # dict of allowed users. (IP address: port socket)

        self.vpn_ip = my_ip
        self.port_pool = deque(range(50000, 50500))  # Available NAT ports
        self.nat_table = []  # format: ((client.src, client.sport), public port, (client.dst, client.dport))
        self.nat_timeouts = {}  # Track last activity time

    def get_socket_dst(self, data=None, ip: str = "") -> None | tuple[str, int]:
        if ip in self.users_addr:
            return self.users_addr[ip]
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
        if packet_data.src in self.users_addr:

            # check addr validity if vm IP is valid
            if self.users_addr[packet_data.src] is not addr:
                print("spoof attack, from:", addr)
                return None

            info_address = (packet_data.src, tcp_udp(packet_data).sport)
            dict_table = {sublist[0]: i for i, sublist in enumerate(self.nat_table)}
            # dict_table format: `(client_vm.src, client.sport): index`
            # index - index of key in the `nat_table`.
            # (client.src, client.sport) is addr
            if info_address not in dict_table:
                # fixme, only check if info_address match; need to check if dst match too, and update nat_table if not

                # append source info address, attach a unique public port, and add destination info
                self.nat_table.append(
                    (info_address,
                     self.port_pool.popleft(),
                     (packet_data[IP].dst, tcp_udp(packet_data).dport))
                )

                index = len(self.nat_table) - 1
            else:
                print("*****"*10, "reusing connection")
                index = dict_table[info_address]

            # update sources
            packet_data[IP].src = self.vpn_ip
            tcp_udp(packet_data).sport = self.nat_table[index][1]  # get the public port

            # update checksum
            # data = update_checksum(bytes(packet_data))
            """del packet_data.chksum
            del tcp_udp(packet_data).chksum
            data = bytes(packet_data)"""
            data = update_checksum(bytes(packet_data))

            return data

        print("non assigned addr:", addr)
        return None  # invalid address

    def internet_recv(self, data: IP) -> IP | None:
        """
        get data in format of scapy, return data with updated destinations
        return address info of the client

        :param data: scapy TCP/UDP packet
        :return: data, client's ip address
        """
        # get layer 4 of the packet
        layer4 = tcp_udp(data)
        if not layer4:
            print("invalid internet packet struct:", data)
            return None

        # vpn public port
        public_port = layer4.dport
        # internet source info
        source_ip = data[IP].src
        source_port = layer4.sport

        dict_table = {sublist[1]: i for i, sublist in enumerate(self.nat_table)}
        if public_port in dict_table:
            index = dict_table[public_port]

            if self.nat_table[index][2] != (source_ip, source_port):
                print("need to update nat_table; unmatch connection:", data)
                return None

            # client address info
            addr = self.nat_table[index][0]

            # ip_header = data[IP]

            # update destinations to client address
            # ip_header.dst = addr[0]  # client VM's IP address
            layer4.dport = addr[1]  # client's original port

            data = IP(dst=addr[0], src=data[IP].src) / layer4
            # tcp_udp(data).dport = addr[1]
            # data = data[IP]

            # might need to write a new packet instead of updating existing packet `data`
            """
            # if i finished answering these problems.
            # try minimize the use of scapy, in order to achieve better performance
            """

            # update checksum
            data = IP(update_checksum(bytes(data)))
            # data contains not enough info in order to
            # extract variables to match `sendto(data, (-, -))`
            # it is missing ip and port.
            # in order to get these, you can use the function `get_socket_dst` in the server code
            return data  # `data` is in format of scapy packet

        print("invalid connection")
        return None

    def cleanup_nat_table(self):
        """Remove stale NAT entries"""
        while True:
            time.sleep(30)
            now = time.time()
            stale = [port for port, t in self.nat_timeouts.items() if now - t > 300]
            for port in stale:
                del self.nat_timeouts[port]
                self.port_pool.append(port)
                self.nat_table = [i for i in self.nat_table if i[1] != port]
            print(f"Cleanup: Removed {len(stale)} entries")
