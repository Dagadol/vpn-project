import socket
import threading

import connect_protocol
import time

this_ip = "10.0.0.13"
client_port = 5500
port_for_vpn = 8888

vpn_servers = dict()  # server IP: socket
client_dict = dict()  # client ID: (socket, thread)
server_handler = connect_protocol.CommandHandler()  # command waiting list


def get_fastest_vpn(exception: str = ""):
    scores = {}  # Store scores for each server

    for ip in vpn_servers:
        if ip == exception:
            continue

        this_thread = threading.get_native_id()  # get this thread id

        # Measure ping
        start_time = time.time()
        vpn_servers[ip].send(connect_protocol.create_msg(f"request~from_id:{this_thread}", "checkup"))
        # print(f"sent to vpn at {ip}, with {vpn_servers[ip]}")

        cmd, msg = server_handler.get_thread_data(vpn_servers[ip], this_thread, 30)
        ping = time.time() - start_time - 2  # Stop measuring. removes 2 to ignore the 2 seconds load calc
        # print(f"cmd: '{cmd}'\tmsg: {msg}")
        if cmd != "checkup":
            print("cmd:", cmd)

            continue  # Invalid response\Server is full, ignore this server

        # Parse response: to_id:{num}~space_left~v_ip~cpu_load
        msg_parts = msg.split("~")
        if len(msg_parts) != 4:
            continue  # Malformed response

        _, space_left, cpu_load, thread_id = msg_parts  # thread_id = "from_id:{num}"

        cpu_load = float(cpu_load)  # Assuming it's sent as a number (percentage, e.g., 30 for 30%)
        space_left = int(space_left)

        if not cpu_load:  # case cpu == 0
            cpu_load += 0.1
        if not ping:  # case ping == 0
            ping += 0.1

        thread_id = f"to_{thread_id.split("_")[1]}"  # thread_id = "to_id:{num}"

        if space_left == 0:
            continue  # Skip this server

        # Calculate priority score
        score = (0.6 / ping) + (0.3 * space_left) + (0.1 / cpu_load)
        scores[ip] = (score, thread_id)
        print("score:", scores[ip])

    # Select the best server
    best_server = max(scores, key=lambda x: scores[x][0], default=None)  # Get server with the highest score
    print(best_server)
    print(scores)
    if not best_server:  # check if got server
        print("no best server")
        return None, None
    # turn scores into a list
    thread_id = scores[best_server][1]  # thread of the server
    del scores[best_server]
    scores = list(scores)

    # Deny servers with no space
    for ip in scores:
        vpn_servers[ip].send(connect_protocol.create_msg(f"{scores[ip][1]}~denied", "checkup0"))

    return best_server, thread_id


def handle_connect(skt, addr, client_id, port):
    server_ip, thread_id = get_fastest_vpn()

    if not server_ip:
        skt.send(connect_protocol.create_msg("no server was found", "connect_0"))
        print("no server was found")
        return False

    data = f"{addr}~{port}~{client_id}"
    vpn_servers[server_ip].send(connect_protocol.create_msg(f"{thread_id}~{data}", "checkup1"))

    # Get VPN data while removing this thread id
    cmd, serer_data = server_handler.get_thread_data(vpn_servers[server_ip], threading.get_native_id())
    _, vpn_port, v_ip = serer_data.split("~")

    # Craft data for client
    data = f"{server_ip}~{vpn_port}~{v_ip}~{addr}"  # vpn_ip~vpn_port~v_ip~client_ip
    skt.send(connect_protocol.create_msg(data, "connect_1"))


def handle_change(skt, addr, client_id, msg):
    connected_server, port, v_addr = msg.split("~")
    server_ip, thread_id = get_fastest_vpn(exception=connected_server)

    if not server_ip:
        skt.send(connect_protocol.create_msg("no server was found", "change_0"))
        return False

    data = f"{addr}~{port}~{client_id}"
    vpn_servers[server_ip].send(connect_protocol.create_msg(f"{thread_id}~{data}", "checkup1"))

    data = f"{server_ip}~{connect_protocol.get_msg(vpn_servers[server_ip])}"  # vpn_ip~vpn_port~v_ip
    skt.send(connect_protocol.create_msg(data, "change_1"))

    disconnect_vpn_by_ip(connected_server, v_addr)  # disconnect previous server


def disconnect_vpn_by_ip(server_ip, v_addr):
    threading_msg = f"from_id:{threading.get_native_id()}"
    try:
        vpn_socket = vpn_servers[server_ip]  # need to check if server_ip is in for error

        # let the vpn know the user has disconnect
        vpn_socket.send(connect_protocol.create_msg(f"{v_addr}~{threading_msg}", "remove"))

        cmd, msg = server_handler.get_thread_data(vpn_socket, threading.get_native_id())
        if cmd != "remove":
            print(f"error at remove: {cmd}, msg: {msg}")

    except KeyError:
        print(f"invalid server ip: {server_ip}; possible cause: server was shutdown so user changed")


def handle_client(skt, addr, client_id):
    while True:
        cmd, msg = connect_protocol.get_msg(skt)
        if cmd == "break":
            continue

        print("command got:", cmd)
        if cmd == "exit":
            if msg != "i want to leave":  # indicates that user is already not connected
                server_ip, v_addr = msg.split('~')
                disconnect_vpn_by_ip(server_ip, v_addr)  # msg hold the vpn ip
                print("user wants to leave")
            else:
                print("user not connected wants to leave")
            del client_dict[client_id]
            skt.close()
            break

        # threads here are unnecessary because client can only send one by one
        elif cmd == "dconnect":
            server_ip, v_addr = msg.split('~')  # msg should hold both server_ip and the v_addr of the user
            # threading.Thread(target=disconnect_vpn_by_ip, args=[server_ip, v_addr]).start()
            disconnect_vpn_by_ip(server_ip, v_addr)

        elif cmd == "connect":
            # threading.Thread(target=handle_client, args=[skt, addr[0], client_id, msg]).start()
            handle_connect(skt, addr[0], client_id, msg)
        elif cmd == "change":
            # threading.Thread(target=handle_change, args=[skt, addr[0], client_id, msg])
            handle_change(skt, addr[0], client_id, msg)


def handle_server_shutdown(msg, vpn_sock):
    clients = msg.split("~")

    vpn_ip = ""
    for skt, ip in vpn_servers.items():
        if skt == vpn_sock:
            vpn_ip = ip

    for client in clients:
        if client not in client_dict:
            print("client ID error:", client)
            continue
        client_skt = client_dict[client][0]  # socket at first index
        thread_msg = client_dict[client][1]  # to thread id at second index
        client_skt.send(connect_protocol.create_msg(f"{thread_msg}~server was closed~{vpn_ip}", "shutdown"))


def wait_for_update(skt, stop_event: threading.Event):
    while True:
        cmd, msg = server_handler.get_thread_data(skt)
        if cmd == "shutdown":
            handle_server_shutdown(msg, skt)
            del vpn_servers[skt]
            skt.close()
            stop_event.set()
            break


def listen_for_servers():
    # continue the code
    servers_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servers_socket.bind((this_ip, port_for_vpn))
    print("VPNs socket is up")

    servers_socket.listen(2)  # two servers
    while True:
        vpn_sock, addr = servers_socket.accept()
        vpn_sock.settimeout(10)
        vpn_sock.send(connect_protocol.create_msg("hello world", "f_conn"))
        print(f"new server connected from: {addr}")

        stop_running = threading.Event()
        threading.Thread(target=server_handler.listen_for_commands, args=[vpn_sock, stop_running]).start()

        vpn_servers[addr[0]] = vpn_sock  # save server
        t = threading.Thread(target=wait_for_update, args=[vpn_sock, stop_running])
        t.start()


def listen_for_clients():
    clients_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clients_socket.bind((this_ip, client_port))

    print("client socket is up")

    clients_socket.listen(5)
    threads = []
    this_id = 0
    while True:
        this_id += 1  # update ID for each user
        client_socket, addr = clients_socket.accept()  # wait for user
        client_socket.settimeout(10)

        client_id = f"client {this_id}"  # make client ID in string
        print(f"new client connected: {client_id}, from {addr}")

        cmd, msg = connect_protocol.get_msg(client_socket)
        if cmd != "f_conn":
            print("error")
            continue

        thread_msg = f"to_{msg.split("_")[1]}"

        client_dict[client_id] = (client_socket, thread_msg)

        t = threading.Thread(target=handle_client, args=[client_socket, addr, client_id])
        t.start()
        threads.append(t)


if __name__ == '__main__':
    # todo: add threads beneath. and apply what need so it will work with the threads in `vpn_server.py`
    t_server = threading.Thread(target=listen_for_servers)
    t_client = threading.Thread(target=listen_for_clients)
    t_server.start()
    t_client.start()
    t_server.join()
    t_client.join()
