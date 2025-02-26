from scapy.all import *
import socket
import hashlib
import nat_class
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

og_gateway_ip = "10.0.0.138"
vpn_server_ip = "10.0.0.20"
# Set virtual adapter
VIRTUAL_ADAPTER_IP = "10.0.0.50"
virtual_adapter_name = "vBOX adapter"
vpn_port = 5123


def first_connection() -> str:
    """

    :return: AES key from the server
    """
    pass


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("0.0.0.0", 8800))  # no need to bind, since server saved client's port and address

    t1 = threading.Thread(target=receive_from_adapter, args=[udp_socket])
    t2 = threading.Thread(target=receive_from_vpn, args=[udp_socket])
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def send_to_vpn(data, sock):
    # encrypt the data first
    data = data
    this_checksum = hashlib.md5(str(bytes(data)).encode()).hexdigest()
    print(this_checksum, "data:", data)
    sock.sendto(this_checksum.encode() + b"~~" + bytes(data), (vpn_server_ip, vpn_port))


def scapy_filter(p):
    if IP in p:
        try:
            if p[IP].src == "10.0.0.5" and nat_class.tcp_udp(p).dport != vpn_port:  # to prevent infinite loop
                return True
        except AttributeError:
            return False
    return False


def receive_from_adapter(s):
    sniff(prn=lambda p: send_to_vpn(p, s), lfilter=scapy_filter, iface="‏‏Ethernet")


def receive_from_vpn(sock):
    while True:
        data, a = sock.recvfrom(65535)
        print("received")
        if a[0] == vpn_server_ip:
            # decrypt data
            data = IP(data)
            print("vpn data:", data)

            send(data, iface="‏‏Ethernet")
            # if data[IP].src == vpn_server_ip:


if __name__ == '__main__':
    main()
