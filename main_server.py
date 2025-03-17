import socket
import threading
import connect_protocol

this_ip = "10.0.0.20"
client_port = 5500
port_for_vpn = 8888
vpn_servers = dict()  # skt: addr


def handle_client(skt, addr):
    while True:
        cmd, msg = connect_protocol.get_msg(skt)


def listen_for_servers():
    # continue the code
    pass


def listen_for_clients():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((this_ip, client_port))

    server_socket.listen(5)
    threads = []
    while True:
        client_socket, addr = server_socket.accept()
        t = threading.Thread(target=handle_client, args=[client_socket, addr])
        t.start()
        threads.append(t)


if __name__ == '__main__':
    main()
