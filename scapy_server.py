import connect_protocol
import nat_class
import socket
from scapy.all import sniff, send
from scapy.layers.inet import IP
import hashlib
import threading


class OpenServer:
    def __init__(self, server_ip, clients: dict = None, keys: dict = None):
        # default_clients = {"10.0.0.50": ("10.0.0.11", 8800)}  # virtual adapter: (skt.ip, skt.port)
        self.clients = clients  # v_addr: (user_ip, user_port)

        # if clients is None. create a value, and enter it the nat class
        # in order to make the nat.users_addr point at self.clients
        if clients is None:
            self.clients["1"] = "2"
        self.nat = nat_class.ClassNAT(my_ip=server_ip, users=self.clients)
        del clients["1"]

        self.keys = keys  # user_ip: key
        self.skt = None

        self.t_recv = threading.Thread(target=self.internet_recv, daemon=True)
        self.t_send = threading.Thread(target=self.internet_send, daemon=True)

        self.conn = False

    def open_conn(self, udp_port):
        if not (self.t_recv.is_alive() and self.t_send.is_alive()) or not self.conn:
            self.conn = True
            # self.clients = clients
            # self.nat.users_addr = self.clients

            self.skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.skt.bind(("0.0.0.0", udp_port))

            self.t_recv.start()
            self.t_send.start()

    def close_conn(self):
        if self.conn:
            self.conn = False
            self.t_recv.join()
            self.t_send.join()
            self.skt = None

    def remove_client(self, v_addr):
        del self.nat.users_addr[v_addr]
        del self.clients[v_addr]

    def update_addr(self):
        self.nat.users_addr = self.clients

    def valid(self, data: bytes, addr) -> bytes | bool:
        if addr not in self.keys:
            print("invalid user")
            return False

        data = data.split(b'~~')

        if data and len(data) == 2:  # ensure data has split correctly
            checksum = data[0]
            encrypted_pkt = data[1]

            this_checksum = hashlib.md5(encrypted_pkt).hexdigest()
            if checksum.decode() == this_checksum:
                # decrypt data, according to this addr key
                pkt = connect_protocol.decrypt(encrypted_pkt, self.keys[addr])
                print("valid checksum:", IP(pkt))

                return pkt
            print("broken checksum:", this_checksum)
        else:
            print("no checksum")
        return False

    def internet_send(self):
        while self.conn:
            data, addr = self.skt.recvfrom(65535)  # receive from client through udp socket

            pkt = self.valid(data, addr[0])
            if pkt:
                new_pkt = self.nat.udp_recv(pkt, addr)

                if new_pkt:
                    new_pkt = IP(new_pkt)
                    print("sending to internet:", new_pkt)
                    send(new_pkt)
                else:
                    print("invalid packet:", pkt)

    def forward_to_client(self, pkt):
        updated_pkt = self.nat.internet_recv(pkt)
        if updated_pkt:
            print("returning to client:", updated_pkt)
            addr = self.nat.get_socket_dst(updated_pkt)  # get the addr info

            # encrypt before sending
            raw_pkt = bytes(updated_pkt)
            encrypted_pkt = connect_protocol.encrypt(raw_pkt, self.keys[addr[0]])

            # add checksum
            checksum = hashlib.md5(encrypted_pkt).hexdigest()  # using md5
            data = checksum.encode() + b"~~" + encrypted_pkt

            self.skt.sendto(data, addr)

    def internet_recv(self):
        while self.conn:
            sniff(prn=lambda p: self.forward_to_client(p), filter="ip", stop_filter=(not self.conn))
            print("sniffed stopped")
