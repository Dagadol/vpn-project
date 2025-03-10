import socket
import threading
import random
import connect_protocol


server_ip = "10.0.0.20"
server_port = 8888
udp_port = 5123  # could be tcp port for aes key, then in there receive the udp port

ADDRESSES = tuple(("10.2.0.1", "10.2.0.2"))  # unchangeable value
available = list(reversed(ADDRESSES))
clients = dict()
keys = dict()  # client_ip: key


def tcp_connection(client_ip, this_port):
    """
    the first connection between the client and this server, represented in tcp
    exchanging keys, and ports.
    :param this_port: tcp_port
    :param client_ip: client's private IP s
    """
    with threading.Lock:
        this_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        this_sock.bind(("0.0.0.0", this_port))  # Bind to all interfaces on `this_port`
        this_sock.listen(1)  # Listen with a backlog of 1 (see below)

        while True:
            conn, addr = this_sock.accept()
            print("Connection from", addr)
            if addr[0] != client_ip:
                print("Unexpected IP, closing connection.")
                conn.close()
                continue
            # Process the connection from the expected IP
            # apply diffie-helman protocol
            shared_key = connect_protocol.dh_send(conn)  # get the shared key

            keys[client_ip] = shared_key  # save the key

            # send over the udp port to the client of this VPN server
            data = connect_protocol.create_msg(str(udp_port), "f_conn", shared_key)  # f stands for first
            conn.send(data)

            break  # break the loop

        conn.close()  # close the temp connection


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
        clients[v_ip] = (client_ip, client_port)


        # vpn server is always on, therefore we don't need to start the thread of it.
        # although I would start a thread for the tcp connection between the client and this server
        threading.Thread(target=tcp_connection, args=[client_ip, tcp_port], daemon=True).start()  # set to daemon
        return True

    else:  # shouldn't get here
        print("checkup problem:", cmd, data)
        return False


def handle_remove(skt, v_addr):
    if v_addr not in clients:
        skt.send(connect_protocol.create_msg("user does not exit", "error"))
    ip = clients[v_addr][0]  # client's ip
    del keys[ip]
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
