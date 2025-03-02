import socket
import connect_protocol


server_ip = "10.0.0.20"
server_port = 8888
udp_port = 5123  # could be tcp port for aes key, then in there receive the udp port

ADDRESSES = tuple(("10.2.0.1", "10.2.0.2"))  # unchangeable value
available = list(reversed(ADDRESSES))
clients = dict()


def handle_checkup(my_socket):
    data = f"{udp_port}~{len(available)}"
    ip = ""
    if available:  # there are available IPs
        ip = available[-1]  # get the last IP from the available list
        data = f"{data}~{ip}"

    my_socket.send(connect_protocol.create_msg(data, f"checkup"))
    cmd, msg = connect_protocol.get_msg(my_socket)

    # checkup0 meaning server doesn't want to assign the user to this vpn server
    if cmd == "checkup0":
        return False
    elif cmd == "checkup1" and ip:  # checkup1 server assign the user to this vpn server
        del available[-1]
        client_ip, client_port = msg.split("~")

        # add new client
        clients[ip] = (client_ip, client_port)

        # vpn server is always on, therefore we don't need to start the thread
        return True

    else:  # shouldn't get here
        print("checkup problem:", cmd, data)
        return False


def handle_remove(skt, v_addr):
    if v_addr not in clients:
        skt.send(connect_protocol.create_msg("user does not exit", "error"))
    del clients[v_addr]
    available.append(v_addr)
    skt.send(connect_protocol.create_msg("user has been removed", "remove"))


def handle_server(my_socket):
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
