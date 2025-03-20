import socket
import threading
import random
import connect_protocol
from scapy_server import OpenServer, tcp_connection


server_ip = "10.0.0.20"
server_port = 8888
udp_port = 5123  # could be tcp port for aes key, then in there receive the udp port

ADDRESSES = tuple(("10.2.0.1", "10.2.0.2"))  # unchangeable value
available = list(reversed(ADDRESSES))
# clients = dict()
# keys = dict()  # client_ip: key

vpn = OpenServer(server_ip, udp_port)


def handle_checkup(my_socket):
    tcp_port = random.randint(udp_port + 1, 6000)
    data = f"{tcp_port}~{len(available)}"  # send the tcp_port, then, if checkup1 send the udp_port
    v_ip = ""  # v stands for virtual. virtual IP given by this server
    if available:  # there are available IPs
        v_ip = available[-1]  # get the last IP from the available list
        data = f"{data}~{v_ip}"

    my_socket.send(connect_protocol.create_msg(data, f"checkup"))
    cmd, msg = connect_protocol.get_msg(my_socket)

    # checkup0 meaning server doesn't want to assign the user to this vpn server
    if cmd == "checkup0":
        return False
    elif cmd == "checkup1" and v_ip:  # checkup1 server assign the user to this vpn server
        del available[-1]
        client_ip, client_port = msg.split("~")

        # add new client
        vpn.clients[v_ip] = (client_ip, client_port)
        vpn.update_addr()

        # vpn server is always on, therefore we don't need to start the thread of it.
        # although I would start a thread for the tcp connection between the client and this server
        threading.Thread(target=tcp_connection, args=[client_ip, tcp_port, vpn], daemon=True).start()  # set to daemon
        return True

    else:  # shouldn't get here
        print("checkup problem:", cmd, data)
        return False


def handle_remove(skt, v_addr):
    global available
    if v_addr not in vpn.clients:
        skt.send(connect_protocol.create_msg("user does not exit", "error"))
    ip = vpn.clients[v_addr][0]  # client's ip

    # remove user's data
    del vpn.keys[ip]
    # let vpn handle the remove
    vpn.remove_client(v_addr)

    # add back the address
    available.append(v_addr)

    # ack
    skt.send(connect_protocol.create_msg("user has been removed", "remove"))

    if not vpn.clients:  # close connection if needed (case no clients)
        vpn.close_conn()
        available = list(reversed(ADDRESSES))  # reset the list of available users


def handle_server(my_socket):  # todo: add thread distribution
    while True:
        cmd, msg = connect_protocol.get_msg(my_socket)
        if cmd == "checkup":
            handle_checkup(my_socket)
        if cmd == "remove":
            handle_remove(my_socket, msg)


def main():
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.connect((server_ip, server_port))

    handle_server(my_socket)
