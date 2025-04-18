import connect_protocol
import nat_class
import socket
from scapy.all import sniff, send
from scapy.layers.inet import IP
import hashlib
import threading


class OpenServer:
    def __init__(self, this_server_ip, server_port, user_amount, clients: dict = None, keys: dict = None):
        # default_clients = {"10.0.0.50": ("10.0.0.11", 8800)}  # virtual adapter: (skt.ip, skt.port)
        self.clients = clients  # v_addr: (user_ip, user_port)
        if self.clients is None:
            self.clients = dict()

        # if clients is None. create a value, and enter it the nat class
        # in order to make the nat.users_addr point at self.clients
        #if clients is None:
        #    self.clients["1"] = "2"
        self.nat = nat_class.ClassNAT(my_ip=this_server_ip, users_amount=user_amount, users=self.clients)
        #del clients["1"]

        self.keys = dict()
        if keys is not None:
            self.keys = keys  # user_ip: key
        self.skt = None

        self.t_recv = None
        self.t_send = None
        self.t_cleanup = None

        self.udp_port = server_port

        self.conn = False

    def open_conn(self):
        if not (self.t_recv and self.t_send) or not self.conn:
            self.conn = True
            # self.clients = clients
            # self.nat.users_addr = self.clients
            self.t_recv = threading.Thread(target=self.internet_recv, daemon=True)
            self.t_send = threading.Thread(target=self.internet_send, daemon=True)
            self.t_cleanup = threading.Thread(target=self.nat.cleanup_nat_table, daemon=True)

            self.skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.skt.bind(("0.0.0.0", self.udp_port))
            self.skt.settimeout(5)

            # start threads
            self.t_recv.start()
            self.t_send.start()
            self.nat.cleanup = True
            self.t_cleanup.start()

    def close_conn(self):
        print("closing connection")
        if self.conn:
            self.conn = False
            self.nat.cleanup = False

            # close threads
            try:
                print("before recv join")
                self.t_recv.join()
                print("before send join")
                self.t_send.join()
                print("before cleanup join")
                self.t_cleanup.join()
            except AttributeError as e:
                print("joined while conn was off:", e)
            self.t_recv = None
            self.t_send = None
            self.t_cleanup = None

            self.skt = None
            print("connection has closed")

    def remove_client(self, v_addr):
        a = self.nat.users_addr.pop(v_addr, None)
        a = self.clients.pop(v_addr, None)

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
                # print("valid checksum:", IP(pkt))

                return pkt
            print("broken checksum:", this_checksum)
        else:
            print("no checksum")
        return False

    def internet_send(self):
        while self.conn:
            try:
                data, addr = self.skt.recvfrom(65535)  # receive from client through udp socket
            except socket.timeout:
                continue

            pkt = self.valid(data, addr[0])
            if pkt:
                new_pkt = self.nat.udp_recv(pkt, addr)

                if new_pkt:
                    new_pkt = IP(new_pkt)
                    # print("sending to internet:", new_pkt)
                    send(new_pkt, verbose=False)
                else:
                    print("invalid packet:", pkt)

    def forward_to_client(self, pkt):
        updated_pkt = self.nat.internet_recv(pkt)
        if updated_pkt:
            # print("returning to client:", updated_pkt)
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
            sniff(prn=lambda p: self.forward_to_client(p), filter="ip", stop_filter=lambda p: (not self.conn))
            print("sniffed stopped")


lock = threading.Lock()


def tcp_connection(client_ip, this_port, vpn: OpenServer):
    """
    the first connection between the client and this server, represented in tcp
    exchanging keys, and ports.
    :param vpn: info holder, server. type OpenServer
    :param this_port: tcp_port
    :param client_ip: client's private IP s
    """
    with lock:
        this_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        this_sock.bind(("0.0.0.0", this_port))  # Bind to all interfaces on `this_port`
        this_sock.listen(1)  # Listen with a backlog of 1 (see below)

        while True:
            print("waiting for connection")
            conn, addr = this_sock.accept()
            print("Connection from", addr)
            if addr[0] != client_ip:
                print("Unexpected IP, closing connection.")
                conn.close()
                continue
            # Process the connection from the expected IP
            # apply diffie-helman protocol
            shared_key = connect_protocol.dh_send(conn)  # get the shared key

            vpn.keys[client_ip] = shared_key  # save the key

            # send over the udp port to the client of this VPN server
            data = connect_protocol.create_msg(str(vpn.udp_port), "f_conn", shared_key)  # f stands for first
            conn.send(data)

            # Add user

            if not vpn.conn:  # activate the thread of vpn if it is not already activated
                vpn.open_conn()
                print("connection opened")
            else:
                print("does not need to activate")

            conn.close()  # close the temp connection
            break  # break the loop
        this_sock.close()


if __name__ == '__main__':
    allowed_clients = dict()
    allowed_clients["10.0.0.50"] = ("10.0.0.12", 8800)
    server = OpenServer(
        this_server_ip="10.0.0.22",
        server_port=8888,
        clients=allowed_clients,
        user_amount=1
    )
    tcp_connection(
        client_ip="10.0.0.12",
        this_port=5123,
        vpn=server
    )

    try:
        server.open_conn()
        # Keep main thread alive while connection is active
        while server.conn:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        server.close_conn()

