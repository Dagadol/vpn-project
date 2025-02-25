from collections import deque

from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether
# from scapy.utils import checksum


def update_checksum(bad_bytes: bytes) -> bytes:  # update checksum using scapy. maybe try with struct later
    # turn bytes to scapy structured
    scapy_struct = Ether(bad_bytes)
    if scapy_struct.haslayer(IP):

        # get the IP and UDP packet
        ip_pkt = scapy_struct[IP]
        higher_pkt = tcp_udp(scapy_struct)

        # easily remove the IP's header checksum
        del ip_pkt.chksum
        del higher_pkt.chksum

    # return bytes(scapy_struct.__class__(bytes(scapy_struct)))
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
    try:
        return p[UDP]
    except IndexError:
        try:
            return p[TCP]
        except IndexError:
            return None


class ClassNAT:
    def __init__(self, users, my_ip):
        if users:
            self.users_addr = users  # users allowed to connect to this server
        else:
            self.users_addr = dict()  # dict of allowed users. (IP address: port socket)

        self.vpn_ip = my_ip
        self.port_pool = deque(range(50000, 50100))  # Available NAT ports
        self.nat_table = []  # format: ((client.src, client.sport), public port, (client.dst, client.dport))

    def get_socket_port(self, data=None, ip: str = "") -> None | tuple[any, any]:
        if ip in self.users_addr:
            return self.users_addr[ip]
        if data:
            try:
                ip = data[IP].dst
                if ip in self.users_addr:
                    port = self.users_addr[ip]
                    return ip, port
                return ip
            except Exception as e:
                print("get_socket_port: ", e)
        return None

    def udp_recv(self, data: bytes, addr) -> bytes | None:  # called udp because data received through a UDP socket
        """
        Translate data source and save in the NAT table.
        - extract data from udp and change the address to server's
        :param data: requests or data received from client
        :param addr: (IP address, udp source port)
        :return: data to send (with updated source IP and source port)
        """
        if addr[0] in self.users_addr:
            # change from bytes to scapy
            packet_data = Ether(data)
            info_address = (addr[0], tcp_udp(packet_data).sport)
            dict_table = {sublist[0]: i for i, sublist in enumerate(self.nat_table)}
            # dict_table format: `(client.src, client.sport): index`
            # index - index of key in the `nat_table`.
            # (client.src, client.sport) is addr
            if info_address not in dict_table:
                # append source info address, attach a unique public port, and add destination info
                self.nat_table.append(
                    (info_address,
                     self.port_pool.popleft(),
                     (packet_data[IP].dst, tcp_udp(packet_data).dport))
                )

                index = len(self.nat_table) - 1
            else:
                index = dict_table[info_address]

            # update sources
            packet_data[IP].src = self.vpn_ip
            tcp_udp(packet_data).sport = self.nat_table[index][1]  # get the public port

            # update checksum
            # data = update_checksum(bytes(packet_data))
            packet_ip = packet_data[IP]
            del packet_ip.chksum
            del tcp_udp(packet_ip).chksum
            data = bytes(packet_data)
            return data

        return None  # invalid address

    def internet_recv(self, data):
        """
        get data in format of scapy, return data with updated destinations
        return address info of the client

        :param data: scapy TCP/UDP packet
        :return: data, client's ip address
        """
        # get layer 4 of the packet
        layer4 = tcp_udp(data)
        if not layer4:
            return None

        # vpn public port
        public_port = layer4.dport
        # internet source info
        source_ip = data[IP].src
        source_port = layer4.sport

        dict_table = {sublist[1]: i for i, sublist in enumerate(self.nat_table)}
        if public_port in dict_table:
            index = dict_table[public_port]
            if self.nat_table[index][2] == (source_ip, source_port):

                # client address info
                addr = self.nat_table[index][0]

                ip_header = data[IP]

                # update destinations to client address
                ip_header.dst = addr[0]  # client's IP address
                layer4.dport = addr[1]  # client's original port

                data = ip_header.remove_payload() / layer4
                # tcp_udp(data).dport = addr[1]
                # data = data[IP]

                # fixme didnt consider changes in the Ethernet header
                # might need to write a new packet instead of updating existing packet `data`
                """
                # example of removing the Ethernet header
                new_packet = ip_header / layer4  # `layer4` contains the load already
                new_packet = update_checksum(new_packet)
                # i still dont know if this is okay
                return new_packet
                # when this packet is sent to user via udp socket
                # the user send this data to itself via `send` method of scapy,
                # I dont know in this case how to treat the Ethernet headers.
                
                # notice that in this code i used Ether()[IP] rather than IP() in order to manipulate the IP headers
                # this is because i dont fully understand scapy
                # and i think there could be issues relating to using IP() and Ether() after sniffing packets 
                
                # if i finished answering these problems.
                # try minimize the use of scapy, in order to achieve better performance
                """

                # update checksum
                data = IP(bytes(data))
                # data contain enough info in order to
                # extract variables to match `sendto(data, (addr, -))`
                # but is missing the port of the socket in place -
                return data  # `data` is in format of scapy packet
        return None
