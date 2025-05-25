import os
import threading
import socket
import random
from collections import defaultdict
import ssl
import psutil  # used for calculating load

from scapy_server import OpenServer, tcp_connection
import connect_protocol


server_ip = "10.0.0.12"
my_private_ip = "10.0.0.12"  # physical

server_port = 8888
udp_port = 5123  # could be tcp port for aes key, then in there receive the udp port

ADDRESSES = tuple(("10.2.0.1", "10.2.0.2"))  # unchangeable value
available = list(reversed(ADDRESSES))
clients = dict()  # v_addr: client_id
handler = connect_protocol.CommandHandler()  # command waiting list
# keys = dict()  # client_ip: key
vpn = OpenServer(my_private_ip, udp_port, user_amount=len(ADDRESSES))
on = True

server_handler = connect_protocol.CommandHandler()  # command waiting list
socket_locks = defaultdict(threading.Lock)

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.check_hostname = False  # We're connecting by IP
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations('server.crt')  # Trust this cert


def send_atomic(skt, data):
    with socket_locks[skt]:
        skt.send(data)


def close_socket(skt):
    skt.close()
    if skt in socket_locks:
        del socket_locks[skt]


def handle_checkup(my_socket, msg):
    thread_part = msg.split("~")[1]  # f"from_id:{num}"
    thread_part = f"to_{thread_part.split("_")[1]}"  # f"to_id:{num}"

    if not available:  # no space left
        send_atomic(my_socket, connect_protocol.create_msg(f"{thread_part}~invalid space", "checkup0"))
        return False

    # remove the space before you take space_left
    v_addr = available[-1]
    del available[-1]

    space_left = len(available) + 1
    load = psutil.cpu_percent(2)
    this_thread = threading.get_native_id()
    data = f"{thread_part}~{space_left}~{load}~from_id:{this_thread}"  # add thread id to the end of data

    # send data ASAP
    send_atomic(my_socket, connect_protocol.create_msg(msg=data, cmd="checkup"))

    # get data back
    cmd, msg = handler.get_thread_data(my_socket, this_thread)

    if cmd == "checkup0":  # server rejection
        available.append(v_addr)  # restore available IPs
        return False
    elif cmd == "checkup1":  # server was assigned
        _, client_ip, client_port, client_id, client_password_1, client_password_2 = msg.split("~")
        client_port = int(client_port)

        # client_ip is the public IP of the client or the private IP if using ZeroTier
        clients[v_addr] = client_id  # save client

        # set tcp_port
        tcp_port = random.randint(udp_port + 1, 6000)  # fixme: could collide with other active ports

        my_password = os.urandom(16).hex()
        data = f"{thread_part}~{tcp_port}~{v_addr}~{my_password}"
        send_atomic(my_socket, connect_protocol.create_msg(data, "checkup1"))

        # add new client
        vpn.clients[v_addr] = (client_ip, client_port)
        print(f"here: {vpn.clients}")
        vpn.update_addr()

        status = tcp_connection(client_ip, tcp_port, vpn, my_private_ip, my_password, client_password_1,
                                client_password_2)
        if status:
            return True
        else:
            available.append(v_addr)
            return False
    else:  # should never get here
        available.append(v_addr)
        print("checkup problem:", cmd, "\t", msg)
        return False


def try_remove(skt, msg):
    client_id, thread_msg = msg.split("~")
    v_addr = [v_addr for v_addr, client in clients.items() if client == client_id]
    if v_addr:
        handle_remove(skt, f"{v_addr[0]}~{thread_msg}")
    else:
        f"to_{thread_msg.split("_")[1]}"
        send_atomic(skt, connect_protocol.create_msg(f"{thread_msg}~user does not exit", "error"))


def handle_remove(skt, msg):
    global available
    v_addr, thread_msg = msg.split("~")
    thread_msg = f"to_{thread_msg.split("_")[1]}"

    if v_addr not in vpn.clients:
        send_atomic(skt, connect_protocol.create_msg(f"{thread_msg}~user does not exit", "error"))
        print("user does not exit")
    ip = vpn.clients[v_addr][0]  # client's ip

    # remove user's data
    del vpn.keys[ip]
    # let vpn handle the remove
    vpn.remove_client(v_addr)

    # add back the address
    available.append(v_addr)

    # ack
    send_atomic(skt, connect_protocol.create_msg(f"{thread_msg}~the user has been removed", "remove"))

    if not vpn.clients:  # close connection if needed (case no clients)
        vpn.close_conn()
        available = list(reversed(ADDRESSES))  # reset the list of available users
    else:
        print(f"vpn clients are: {vpn.clients}")


def handle_shutdown(skt):
    """
    update server for closing connection, sending the server the clients connected
    :param skt:
    """
    global on
    on = False
    print("Bye World!")
    handler.turn_off()  # set server closed
    vpn.close_conn()

    str_clients = ""
    for v_addr in clients:
        str_clients = clients[v_addr] + "~"
    data = str_clients[0:-1]

    if not data:  # if no users connected
        data = "none"

    send_atomic(skt, connect_protocol.create_msg(data, "shutdown"))
    # close connection
    close_socket(skt)


def handle_server(my_socket):
    while on:
        cmd, msg = handler.get_thread_data(my_socket)
        if msg:
            print("msg:", msg)

        if cmd == "checkup":
            print("checkup:", msg)
            threading.Thread(target=handle_checkup, args=[my_socket, msg]).start()
        elif cmd == "remove":
            print("remove:", msg)
            threading.Thread(target=handle_remove, args=[my_socket, msg]).start()
        elif cmd == "end-conn":
            threading.Thread(target=try_remove, args=[my_socket, msg]).start()
        elif cmd == "break":  # no msg was incoming
            continue
        else:
            print(f"unknown command: '{cmd}'\nmsg received: {msg}")


def main():
    my_socket = socket.create_connection((server_ip, server_port))
    secure_skt = context.wrap_socket(my_socket, server_hostname=server_ip)
    secure_skt.settimeout(5)

    socket_locks[secure_skt] = threading.Lock()

    threading.Thread(target=handler.listen_for_commands, args=[secure_skt]).start()
    print("listening for commands")
    try:
        handle_server(secure_skt)
    except (KeyboardInterrupt, Exception):
        print("VPN server is shutting down")
    finally:
        handle_shutdown(secure_skt)
        my_socket.close()


if __name__ == '__main__':
    main()
