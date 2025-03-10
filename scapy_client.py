import socket
import hashlib
import threading
from scapy.all import sniff, send

import connect_protocol
import nat_class
from scapy.layers.inet import IP
from vpn_client import connected


# todo, all the settings beneath automatically; according to the vpn server or main server instructions
# vpn_server_ip = "10.0.0.20"

# Set virtual adapter manually
# virtual_adapter_ip = "10.0.0.50"
# virtual_adapter_name = "wrgrd"  # wireguard tunnel
# vpn_port = 5123
# my_port = 8800

# private_ip = "10.0.0.11"


def first_connection() -> bytes | None:
    """
    get shared key, and set the correct port of the vpn server
    :return: AES key from the server or None in case of an error
    """
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            my_socket.connect((connected[1].vpn_ip, connected[1].vpn_port))
            break
        except Exception as e:
            print("error at first connection\n", e)

    shared_key = connect_protocol.dh_get(my_socket)

    # receive the correct vpn_port
    cmd, data = connect_protocol.get_msg(my_socket, True)

    my_socket.close()  # close connection
    if cmd != "f_conn":
        print("error at first connection:", cmd, data)
        return None

    # set the port
    udp_port = connect_protocol.decrypt(data, shared_key)
    connected[1].vpn_port = udp_port

    return shared_key  # return the key


def start_connection():
    print("connecting to server")
    key = first_connection()
    if key:

        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind((connected[1].private_ip, connected[1].my_port))

        t1 = threading.Thread(target=receive_from_adapter, args=[udp_socket, key])
        t2 = threading.Thread(target=receive_from_vpn, args=[udp_socket, key])
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # close connection
        udp_socket.close()
        print("udp socket was closed")


def send_to_vpn(data, sock, key):
    # encrypt the data first
    data = bytes(data)
    data = connect_protocol.encrypt(data, key)

    this_checksum = hashlib.md5(data).hexdigest()
    print(this_checksum, "data:", data)
    sock.sendto(this_checksum.encode() + b"~~" + data, (connected[1].vpn_ip, connected[1].vpn_port))


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
        if not connected[1].active:
            print("current thread is closing")
            return True
        else:
            return False
    return True


def receive_from_adapter(s, k):
    """
    sniff of the virtual interface, send over to server via Ethernet interface
    :param k: key
    :param s: UDP socket
    :return:
    """
    sniff(prn=lambda p: send_to_vpn(p, s, k), lfilter=scapy_filter, iface=connected[0].name(),
          stop_filter=active_thread)
    print("closing confirmed from sniff")


def receive_from_vpn(sock, key):
    while not active_thread():
        data, a = sock.recvfrom(65535)
        print("received")
        if a[0] == connected[1].vpn_ip:
            # decrypt data
            data = connect_protocol.decrypt(data, key)

            data = IP(data)
            print("vpn data:", data)

            send(data)
            # if data[IP].src == vpn_server_ip:
    print("closing confirmed from udp")


if __name__ == '__main__':
    start_connection()
