import nat_class
import socket
from scapy.all import sniff, send
from scapy.layers.inet import IP
import hashlib
import threading

clients = {"10.0.0.50": ("10.0.0.11", 8800)}  # virtual adapter: (skt.ip, skt.port)
nat = nat_class.ClassNAT(my_ip="10.0.0.20", users=clients)
socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socket.bind(("0.0.0.0", 5123))


def add_user(addr):
    nat.users_addr[addr[0]] = addr[1]


def main():
    t_recv = threading.Thread(target=internet_recv, args=[socket], daemon=True)
    t_send = threading.Thread(target=internet_send, args=[socket], daemon=True)
    t_recv.start()
    t_send.start()
    t_recv.join()
    t_send.join()


def valid(data: bytes) -> bytes | bool:
    data = data.split(b'~~')
    if len(data) == 2:
        checksum = data[0]
        pkt = data[1]

        checksum2 = hashlib.md5(str(pkt).encode()).hexdigest()
        if checksum.decode() == checksum2:
            print("valid checksum:", IP(pkt))
            return pkt
        print("broken checksum:", IP(pkt))
    return False


def internet_send(skt):
    while True:
        data, addr = skt.recvfrom(65535)  # receive from client through udp socket
        pkt = valid(data)
        if pkt:
            new_pkt = nat.udp_recv(pkt, addr)

            if new_pkt:
                new_pkt = IP(new_pkt)
                print("sending to internet:", new_pkt)
                send(new_pkt)
                # save client's udp port
                if addr[0] not in clients:
                    clients[addr[0]] = addr[1]
                    print("new client saved: ", addr)  # should not get here
            else:
                print("invalid packet:", pkt)


def forward_to_client(pkt, skt):
    data = nat.internet_recv(pkt)
    if data:
        print("returning to client:", data)
        addr = nat.get_socket_dst(data)
        skt.sendto(bytes(data), addr)


def internet_recv(s):
    while True:
        sniff(prn=lambda p: forward_to_client(p, s), filter="ip")
        print("sniffed stopped")


if __name__ == '__main__':
    main()
