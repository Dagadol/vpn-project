from collections import defaultdict, deque
import threading
import socket
import random
import atexit
import psutil  # used for calculating load
import time
from scapy_server import OpenServer, tcp_connection
import connect_protocol


server_ip = "10.0.0.20"
server_port = 8888
udp_port = 5123  # could be tcp port for aes key, then in there receive the udp port

ADDRESSES = tuple(("10.2.0.1", "10.2.0.2"))  # unchangeable value
available = list(reversed(ADDRESSES))
clients = dict()  # v_addr: client_id
requests_cmd = defaultdict()  # command waiting list
# keys = dict()  # client_ip: key
on = True
vpn = OpenServer(server_ip, udp_port)


def handle_checkup(my_socket):
    if not available:  # no space left
        my_socket.send("invalid space", "checkup0")
        return False

    # remove the space before you take space_left
    v_addr = available[-1]
    del available[-1]

    space_left = len(available) + 1
    load = psutil.cpu_percent()
    data = f"{space_left}~{load}"

    # send data ASAP
    my_socket.send(connect_protocol.create_msg(data=data, cmd="checkup"))
    cmd, msg = connect_protocol.get_msg(my_socket)

    if cmd == "checkup0":  # server rejection
        available.append(v_addr)  # restore available IPs
        return False
    elif cmd == "checkup1":  # server was assigned
        client_ip, client_port, client_id = msg.split("~")
        clients[v_addr] = client_id  # save client

        # set tcp_port
        tcp_port = random.randint(udp_port + 1, 6000)

        data = f"{tcp_port}~{v_addr}"
        my_socket.send(connect_protocol.create_msg(data, "checkup"))

        # add new client
        vpn.clients[v_addr] = (client_ip, client_port)
        vpn.update_addr()

        threading.Thread(target=tcp_connection, args=[client_ip, tcp_port, vpn], daemon=True).start()  # set to daemon
        return True
    else:  # should never get here
        available.append(v_addr)
        print("checkup problem:", cmd, "\t", msg)
        return False


"""def handle_checkup2(my_socket):
    tcp_port = random.randint(udp_port + 1, 6000)
    space_left = len(available)  # space for new users

    data = f"{tcp_port}~{space_left}"  # send the tcp_port, then, if checkup1 send the udp_port
    v_ip = ""  # v stands for virtual. virtual IP given by this server

    if available:  # there are available IPs
        v_ip = available[-1]  # get the last IP from the available list
        data = f"{data}~{v_ip}"
    else:
        data = data + "~0"  # at the end, data will be formatted: tcp_port~space_left~v_ip

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
"""


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


def handle_shutdown(skt):
    """
    update server for closing connection, sending the server the clients connected
    :param skt:
    """
    global on
    print("bye world")
    on = False  # set server closed

    str_clients = ""
    for v_addr in clients:
        str_clients = clients[v_addr] + "~"
    data = str_clients[0:-1]
    skt.send(connect_protocol.create_msg(data, "shutdown"))
    # close connection
    skt.close()


def listen_for_commands(skt):
    global requests_cmd
    while on:
        cmd, msg = connect_protocol.get_msg(skt)
        thread = int(msg.split('~')[0])

        if thread in requests_cmd:
            requests_cmd[thread].append((cmd, msg))  # No need to convert list
        else:
            requests_cmd[thread] = deque([(cmd, msg)])  # Use deque instead of list


def get_command():
    global requests_cmd
    this_thread = threading.get_native_id()
    start = time.time()

    while time.time() - start < 5:
        if this_thread in requests_cmd:
            queue = requests_cmd[this_thread]
            if queue:
                cmd, msg = queue.popleft()  # Remove oldest message efficiently
                if not queue:
                    del requests_cmd[this_thread]  # Cleanup if empty
                return cmd, msg
        time.sleep(0.01)  # Prevent busy waiting

    return "break", None  # Timeout case


def handle_server(my_socket):  # todo: add thread distribution
    while on:
        cmd, msg = connect_protocol.get_msg(my_socket)
        if cmd == "checkup":
            threading.Thread(target=handle_checkup, args=[my_socket], daemon=True).start()
        if cmd == "remove":
            threading.Thread(target=handle_remove, args=[my_socket, msg], daemon=True).start()
        if cmd == "break":
            continue


def main():
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    atexit.register(handle_shutdown)  # activate on exit

    my_socket.connect((server_ip, server_port))

    # let the Main server know the max users available
    max_users = str(len(ADDRESSES))
    my_socket.send(connect_protocol.create_msg(max_users, "vpn_in"))

    handle_server(my_socket)


if __name__ == '__main__':
    main()
