import socket
import threading

import connect_protocol
import db_communication
import time

this_ip = "10.0.0.14"
# this_ip = "172.29.168.164"  # Your main server's ZeroTier IP

client_port = 5500
port_for_vpn = 8888
list_of_allowed_VPNs = {"0.0.0.0": "Any", "10.0.0.12": "Israel"}  # {VPN IP: country} - Any is default for all countries
# might use API of IP tracker. But manually assigning the country is perfectly fine as well

vpn_servers = dict()  # server IP: socket
client_dict = dict()  # {client ID: (socket, thread)}
# the thread is used for the client in `server_connection` function

server_handler = connect_protocol.CommandHandler()  # command waiting list


def get_fastest_vpn(country_filter: str = "Any", exception: str = ""):
    """
    get the best server info according to the country filter, exception, relative ping to this server and server load.

    :param country_filter: country that the client wish to connect to. allowed to verified users
    :param exception: exception is server not to connect, should be the server that the client is connected to
    :return: best_server, server_thread
    best_server:
    "best" server in the country that was specified according to ping relative to server and cpu %.

    server_thread:
    each server has its own thread everytime a new command is executed (in this case: "checkup").
    if thread is not specified the command will initiate a new thread.
    """
    scores = {}  # Store scores for each server

    for ip in vpn_servers:
        if ip == exception or (country_filter != "Any" and country_filter != list_of_allowed_VPNs[ip]):
            continue

        this_thread = threading.get_native_id()  # get this thread id

        # Measure ping
        start_time = time.time()
        vpn_servers[ip].send(connect_protocol.create_msg(f"request~from_id:{this_thread}", "checkup"))
        print(f"sent to vpn at {ip}, with {vpn_servers[ip]}")

        cmd, msg = server_handler.get_thread_data(vpn_servers[ip], this_thread, 30)
        ping = time.time() - start_time - 2  # Stop measuring. removes 2 to ignore the 2 seconds load calc
        print(f"cmd: '{cmd}'\tmsg: {msg}")
        if cmd != "checkup":
            print("bad cmd:", cmd)

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
        # print("score:", scores[ip])

    # Select the best server
    best_server = max(scores, key=lambda x: scores[x][0], default=None)  # Get server with the highest score
    print(f"server chosen: {best_server}")
    # print(scores)
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


def handle_connect(skt, addr, client_id, msg, client):
    port, country, client_code_1, client_code_2 = msg.split("~")

    if not (client.is_verified or country == "Any"):
        country = "Any"
    server_ip, thread_id = get_fastest_vpn(country)

    if not server_ip:
        skt.send(connect_protocol.create_msg("no server was found", "connect_0"))
        print("no server was found")
        return False

    status = connect_by_ip(server_ip, client_id, port, skt, addr, thread_id, client_code_1, client_code_2)
    if not status:
        print(f"unable to connect: {status}")
        # notify user


def connect_by_ip(server_ip, client_id, port, skt, addr, thread_id, client_code_1, client_code_2):
    data = f"{addr}~{port}~{client_id}~{client_code_1}~{client_code_2}"
    vpn_servers[server_ip].send(connect_protocol.create_msg(f"{thread_id}~{data}", "checkup1"))

    # Get VPN data
    cmd, server_data = server_handler.get_thread_data(vpn_servers[server_ip], threading.get_native_id())
    _, vpn_port, v_ip, server_code = server_data.split("~")  # v stands for virtual

    # Craft data for client
    data = f"{server_ip}~{vpn_port}~{v_ip}~{server_code}"  # vpn_ip~vpn_port~v_ip

    # Simple validation
    if cmd == "checkup1":
        skt.send(connect_protocol.create_msg(data, "connect_1"))
        return True
    elif cmd == "checkup0":
        print("something happened, VPN rejected")
        return False

    print(f"false command: {cmd}")
    return False  # shouldn't get here


def handle_change(skt, addr, client_id, msg, client):
    connected_server, port, v_addr, country, client_code_1, client_code_2 = msg.split("~")

    if not (client.is_verified or country == "Any"):
        country = "Any"

    server_ip, thread_id = get_fastest_vpn(country, exception=connected_server)

    if not server_ip:
        skt.send(connect_protocol.create_msg("no server was found", "change_0"))
        return False

    status = connect_by_ip(server_ip, client_id, port, skt, addr, thread_id, client_code_1, client_code_2)
    if status:
        disconnect_vpn_by_ip(connected_server, v_addr)  # disconnect previous server
    else:
        pass  # notify user


def disconnect_vpn_by_ip(server_ip, v_addr):
    threading_msg = f"from_id:{threading.get_native_id()}"
    try:
        if server_ip not in vpn_servers:
            print("server is not available")
            return

        vpn_socket = vpn_servers[server_ip]  # need to check if server_ip is in for error

        # let the vpn know the user has disconnect
        vpn_socket.send(connect_protocol.create_msg(f"{v_addr}~{threading_msg}", "remove"))

        cmd, msg = server_handler.get_thread_data(vpn_socket, threading.get_native_id(), block=10)
        if cmd != "remove":
            print(f"error at remove: {cmd}, msg: {msg}")

    except KeyError:
        print(f"invalid server ip: {server_ip}; possible cause: server was shutdown so user changed")
        # another possible cause, is if user is a hacker and tried to do something fishi


def try_login(client) -> bool:
    if not client.is_registered():
        # is not registered
        return False

    client.get_user_id()  # setting the ID
    if not client.valid_login():
        # passwords do not match
        return False

    client.get_role()  # save role
    return True


def try_signup(client) -> bool:
    if client.is_registered():
        # already registered
        return False

    client.insert_client()
    client.get_user_id()  # set ID
    return True


def refresh_countries(skt, this_client):
    if this_client.is_verified:
        countries = ["Any"] + [list_of_allowed_VPNs[key] for key in list_of_allowed_VPNs if key in vpn_servers]
        countries = "~".join(countries)  # maybe later use json to wrap this
        skt.send(connect_protocol.create_msg(countries, "countries"))
        return True
    return False


def handle_login(skt, addr, client_id):
    # todo add client_id to db_communication.Client as attribute
    login = False
    this_client = None
    while not login:
        cmd, msg = connect_protocol.get_msg(skt)
        if cmd == "break":
            if msg != "timeout error":
                # suspicious activity  -  timeout error is the only error acceptable
                break
            continue
        elif cmd == "exit":
            print("user left the program")
            break
        elif not (cmd == "signup" or cmd == "login"):
            print("error at waiting to login cmd:", cmd, "msg:", msg)
            break

        print("cmd:", cmd, "msg:", msg)
        email, password = msg.split("~")
        this_client = db_communication.Client(email, password)

        if cmd == "login":
            login = try_login(this_client)
            reason = "email or password incorrect"
        else:
            login = try_signup(this_client)
            reason = "user exist already"

        if not login:  # status (was able to log in/signup)
            data = connect_protocol.create_msg(reason, "fail")
            print("data sent:", data)
            skt.send(data)

    if not this_client:
        """get here if user breaks/exit"""
        # skt.send(connect_protocol.create_msg("error", "fail"))  # might not be needed
        del client_dict[client_id]
        skt.close()

    if login and this_client:
        data = connect_protocol.create_msg(f"{this_client.role}~{this_client.is_verified}", "success")
        print("data sent:", data)
        skt.send(data)

        # send to client the available countries, also possible to send on login
        refresh_countries(skt, this_client)

        handle_client(skt, addr, client_id, this_client)


def disconnect_from_all(client_id):  # todo
    """tell to all servers to remove this ID"""
    thread_id = threading.get_native_id()
    for vpn_skt in vpn_servers.values():
        vpn_skt.send(connect_protocol.create_msg(f"{client_id}~from_id:{thread_id}", "end-conn"))
        cmd, _ = server_handler.get_thread_data(vpn_skt, thread_id)
        if cmd == "remove":
            print("user successfully removed")
            return
    print("user was not connected")


def handle_client(skt, addr, client_id, client):
    logout = False
    while True:
        cmd, msg = connect_protocol.get_msg(skt)
        if cmd == "break":
            if msg == "timeout error":
                continue
            # todo: continue what you wanted to do here
            cmd = "exit"
            msg = "force exit"

        print("command got:", cmd)
        if cmd == "exit":
            if msg != "i want to leave" and msg != "force exit":  # indicates that user is already not connected
                server_ip, v_addr = msg.split('~')
                print(f"user connected wants to leave from {server_ip}")
                disconnect_vpn_by_ip(server_ip, v_addr)  # msg hold the vpn ip
            elif msg == "i want to leave":
                print("user not connected wants to leave")
            else:
                print("user ended task")
                disconnect_from_all(client_id)
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
            handle_connect(skt, addr[0], client_id, msg, client)
        elif cmd == "change":
            # threading.Thread(target=handle_change, args=[skt, addr[0], client_id, msg])
            handle_change(skt, addr[0], client_id, msg, client)
        elif cmd == "countries":
            status = refresh_countries(skt, client)
            if not status:
                # very suspicious activity
                pass
        elif cmd == "logout":
            logout = True
            if msg != "i want to leave":
                server_ip, v_addr = msg.split('~')
                disconnect_vpn_by_ip(server_ip, v_addr)  # msg hold the vpn ip
            break

    if logout:
        handle_login(skt, addr, client_id)


def handle_server_shutdown(msg, vpn_ip):
    if msg == "none":
        print("server without user was disconnected")
        return

    clients = msg.split("~")

    # vpn_ip = ""
    # for skt, ip in vpn_servers.items():
    #     if skt == vpn_sock:
    #         vpn_ip = ip

    for client in clients:
        if client not in client_dict:
            print("client ID error:", client)
            continue
        client_skt = client_dict[client][0]  # socket at first index
        thread_msg = client_dict[client][1]  # to thread id at second index
        client_skt.send(connect_protocol.create_msg(f"{thread_msg}~server was closed~{vpn_ip}", "shutdown"))


def wait_for_update(skt, vpn_ip, stop_event: threading.Event):
    global vpn_servers
    while True:
        cmd, msg = server_handler.get_thread_data(skt)
        if cmd == "shutdown":
            handle_server_shutdown(msg, vpn_ip)
            print("server saved:", vpn_servers)
            del vpn_servers[vpn_ip]  # forget vpn
            stop_event.set()
            skt.close()
            break


def listen_for_servers():
    # continue the code
    servers_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servers_socket.bind((this_ip, port_for_vpn))
    print("VPNs socket is up")

    servers_socket.listen(2)  # two servers
    while True:
        vpn_sock, addr = servers_socket.accept()

        # check if IP address is valid
        if len(list_of_allowed_VPNs) > 1:  # if list was created with values
            if addr[0] not in list_of_allowed_VPNs:
                vpn_sock.close()
                continue

        vpn_sock.send(connect_protocol.create_msg("hello world", "f_conn"))
        print(f"new server connected from: {addr}")

        stop_running = threading.Event()
        threading.Thread(target=server_handler.listen_for_commands, args=[vpn_sock, stop_running]).start()

        vpn_servers[addr[0]] = vpn_sock  # save server
        t = threading.Thread(target=wait_for_update, args=[vpn_sock, addr[0], stop_running])
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

        t = threading.Thread(target=handle_login, args=[client_socket, addr, client_id])
        t.start()
        threads.append(t)


if __name__ == '__main__':
    t_server = threading.Thread(target=listen_for_servers)
    t_server.start()
    listen_for_clients()
    t_server.join()
