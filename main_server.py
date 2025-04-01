import socket
import threading
import connect_protocol
import time

this_ip = "10.0.0.20"
client_port = 5500
port_for_vpn = 8888

vpn_servers = dict()  # server IP: socket
client_dict = dict()  # client ID: socket


def get_fastest_vpn(exception: str = ""):
    scores = {}  # Store scores for each server

    for ip in vpn_servers:
        if ip == exception:
            continue

        # Measure ping
        start_time = time.time()
        vpn_servers[ip].send(connect_protocol.create_msg("request", "checkup"))
        cmd, msg = connect_protocol.get_msg(vpn_servers[ip])
        ping = time.time() - start_time  # Stop measuring

        if cmd != "checkup":
            continue  # Invalid response, ignore this server

        # Parse response: tcp_port~space_left~v_ip~cpu_load
        msg_parts = msg.split("~")
        if len(msg_parts) != 2:
            continue  # Malformed response

        space_left, cpu_load = msg_parts
        space_left = int(space_left)
        cpu_load = float(cpu_load)  # Assuming it's sent as a number (percentage, e.g., 30 for 30%)

        if space_left == 0:
            continue  # Skip this server

        # Calculate priority score
        score = (0.6 / ping) + (0.3 * space_left) + (0.1 / cpu_load)
        scores[ip] = score

    # Select the best server
    best_server = max(scores, key=scores.get, default=None)  # Get server with the highest score

    # turn scores into a list
    del scores[best_server]
    scores = list(scores)

    # Deny servers with no space
    for ip in scores:
        vpn_servers[ip].send(connect_protocol.create_msg("denied", "checkup0"))

    return best_server


def handle_connect(skt, addr, client_id, port):
    server_ip = get_fastest_vpn()

    if not server_ip:
        skt.send(connect_protocol.create_msg("no server was found", "connect_0"))
        return False

    data = f"{addr}~{port}~{client_id}"
    vpn_servers[server_ip].send(connect_protocol.create_msg(data, "checkup1"))

    data = f"{server_ip}~{connect_protocol.get_msg(vpn_servers[server_ip])}~{addr}"  # vpn_ip~vpn_port~v_ip~client_ip
    skt.send(connect_protocol.create_msg(data, "connect_1"))


def handle_change(skt, addr, client_id, msg):
    connected_server, port, v_addr = msg.split("~")
    server_ip = get_fastest_vpn(exception=connected_server)

    if not server_ip:
        skt.send(connect_protocol.create_msg("no server was found", "change_0"))
        return False

    data = f"{addr}~{port}~{client_id}"
    vpn_servers[server_ip].send(connect_protocol.create_msg(data, "checkup1"))

    data = f"{server_ip}~{connect_protocol.get_msg(vpn_servers[server_ip])}"  # vpn_ip~vpn_port~v_ip
    skt.send(connect_protocol.create_msg(data, "change_1"))

    disconnect_vpn_by_ip(connected_server, v_addr)  # disconnect previous server


def disconnect_vpn_by_ip(server_ip, v_addr):
    try:
        vpn_socket = vpn_servers[server_ip]  # need to check if server_ip is in for error
        vpn_socket.send(connect_protocol.create_msg(v_addr, "remove"))  # let the vpn know the user has removed

        connect_protocol.get_msg(vpn_socket)
    except KeyError:
        print(f"invalid server ip: {server_ip}, received from user")


def handle_client(skt, addr, client_id):
    while True:
        cmd, msg = connect_protocol.get_msg(skt)
        if cmd == "exit":
            if msg != "i want to leave":  # indicates that user is already not connected
                server_ip, v_addr = msg.split('~')
                disconnect_vpn_by_ip(server_ip, v_addr)  # msg hold the vpn ip

            del client_dict[client_id]
            skt.close()
            break

        elif cmd == "dconnect":
            server_ip, v_addr = msg.split('~')  # msg should hold both server_ip and the v_addr of the user
            disconnect_vpn_by_ip(server_ip, v_addr)

        elif cmd == "connect":
            handle_connect(skt, addr[0], client_id, msg)
        elif cmd == "change":
            handle_change(skt, addr[0], client_id, msg)


def wait_for_update(vpn_sock):



def listen_for_servers():
    # continue the code
    servers_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servers_socket.bind((this_ip, port_for_vpn))

    servers_socket.listen(2)  # two servers
    while True:
        vpn_sock, addr = servers_socket.accept()

        vpn_servers[addr[0]] = vpn_sock  # save server
        t = threading.Thread(target=wait_for_update, daemon=True)
        t.start()


def listen_for_clients():
    clients_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clients_socket.bind((this_ip, client_port))

    clients_socket.listen(5)
    threads = []
    this_id = 0
    while True:
        this_id += 1  # update ID for each user
        client_socket, addr = clients_socket.accept()  # wait for user

        client_id = f"client {this_id}"  # make client ID in string
        client_dict[client_id] = client_socket

        t = threading.Thread(target=handle_client, args=[client_socket, addr])
        t.start()
        threads.append(t)


if __name__ == '__main__':
    # todo: add threads beneath. and apply what need so it will work with the threads in `vpn_server.py`
    listen_for_servers()
    listen_for_clients()
