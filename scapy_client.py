import socket
import hashlib
import threading
from scapy.all import sniff, send
import nat_class
from scapy.layers.inet import IP
from vpn_client import connected


# todo, all the settings beneath automatically; according to the vpn server or main server instructions
og_gateway_ip = "10.0.0.138"
# vpn_server_ip = "10.0.0.20"

# Set virtual adapter manually
# virtual_adapter_ip = "10.0.0.50"
# virtual_adapter_name = "wrgrd"  # wireguard tunnel
# vpn_port = 5123
# my_port = 8800

# private_ip = "10.0.0.11"


def first_connection() -> str:
    """

    :return: AES key from the server
    """
    pass


def start_connection():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((connected[1].private_ip, connected[1].my_port))
    print("connecting to server")
    t1 = threading.Thread(target=receive_from_adapter, args=[udp_socket])
    t2 = threading.Thread(target=receive_from_vpn, args=[udp_socket])
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # close connection
    udp_socket.close()
    print("udp socket was closed")


def send_to_vpn(data, sock):
    # encrypt the data first
    data = data
    this_checksum = hashlib.md5(str(bytes(data)).encode()).hexdigest()
    print(this_checksum, "data:", data)
    sock.sendto(this_checksum.encode() + b"~~" + bytes(data), (connected[1].vpn_ip, connected[1].vpn_port))


def scapy_filter(p):
    if IP in p:
        try:
            # to prevent infinite loop
            if (p[IP].src == connected[0].ip and
                    not nat_class.tcp_udp(p).dport == connected[1].vpn_port):  # FROM adapter; NOT to VPN;
                return True
        except AttributeError:
            return False
    return False


def active_thread():
    if connected:
        return not connected[1].active
    return True


def receive_from_adapter(s):
    """
    sniff of the virtual interface, send over to server via Ethernet interface
    :param s: UDP socket
    :return:
    """
    sniff(prn=lambda p: send_to_vpn(p, s), lfilter=scapy_filter, iface=connected[0].name(), stop_filter=active_thread)


def receive_from_vpn(sock):
    while not active_thread():
        data, a = sock.recvfrom(65535)
        print("received")
        if a[0] == connected[1].vpn_ip:
            # decrypt data
            data = IP(data)
            print("vpn data:", data)

            send(data)
            # if data[IP].src == vpn_server_ip:


if __name__ == '__main__':
    start_connection()
