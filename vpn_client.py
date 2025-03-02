import random
import subprocess
import socket
import threading
from scapy_client import start_connection
import connect_protocol
from adapter_conf import Adapter, Connection

connected = tuple()
vpn_thread = threading.Thread(target=start_connection)
main_server_addr = ("10.0.0.20", 5500)

avail_commands = """
Connect: connect to best vpn server
Disconnect: disconnect from current vpn server
Change: change vpn server
Exit: shutdown application
Else: show list of commands
"""


def handle_exit(skt):
    return handle_disconnect(skt, "shutdown")


def handle_connect(skt):
    global connected
    if connected:
        print("unable to connect: already connected")
        return False

    port = random.randint(50600, 54000)
    while port in subprocess.run("netstat -n", capture_output=True, text=True, shell=True):  # if port is in use
        port = random.randint(50600, 54000)  # create new port

    skt.send(connect_protocol.create_msg(str(port), "connect"))  # could be used later after database
    cmd, msg = connect_protocol.get_msg(skt)  # should return (vpn_ip~vpn_port~vm_ip~my_private_ip)

    if cmd == "connect_0":  # server does not allow connection
        print("try to connect later:", msg)
        return False
    elif cmd != "connect_1":  # server did not return the correct command
        print("error happened at connection:", cmd, msg)
        return False

    vpn_ip, vpn_port, vm_ip, my_ip = msg.split("~")
    v_interface = Adapter(vm_ip)
    connection_settings = Connection(vpn_ip=vpn_ip, vpn_port=vpn_port, my_port=port, my_ip=my_ip)
    connected = (v_interface, connection_settings)

    # key should be received in `scapy_client.py`

    # start the vpn thread
    connected[1].active = True  # let scapy client know it's active (simplified event)
    vpn_thread.start()

    return True


def handle_disconnect(skt, cmd: str = "dconnect"):
    global connected
    if not connected:
        print("already disconnected")

    vpn = connected[1].vpn_ip  # connected vpn server's ip
    subnet_ip = connected[0].ip  # virtual interface ip
    skt.send(connect_protocol.create_msg(vpn + "~" + subnet_ip, cmd))  # let the server handle the vpn server

    # handle client side disconnection
    connected[1].active = False
    vpn_thread.join()
    print("disconnected from vpn connection")

    # remove adapter
    connected[0].delete_adapter()
    connected = tuple()

    return True


def handle_change(skt):
    if not connected:
        print("is not connected")
        return False
    vpn = connected[1].vpn_ip
    subnet_ip = connected[0].ip
    skt.send(connect_protocol.create_msg(vpn + "~" + subnet_ip, "change"))  # let the server handle the vpn server
    cmd, msg = connect_protocol.get_msg(skt)  # should return (vpn_ip~vpn_port~vm_ip~my_private_ip)
    if cmd == "change_0":
        print("unable to change server:", msg)
        return False
    elif cmd != "change_1":
        print("error happened at changing servers:", cmd, msg)
        return False

    # ending thread
    connected[1].active = False
    print("disconnecting from vpn server")
    vpn_thread.join()
    print("successfully disconnected")

    vpn_ip, vpn_port, vm_ip = msg.split("~")

    connected[1].vpn_ip = vpn_ip
    connected[1].vpn_port = vpn_port
    connected[0].update_ip(vm_ip)

    connected[1].active = True
    vpn_thread.start()

    return True


def wait_for_command(skt):
    commands = {"connect": handle_connect,
                "disconnect": handle_disconnect,
                "change": handle_change,
                "exit": handle_exit}
    while True:
        command = input("enter command: ").lower()
        if command not in commands:
            print(avail_commands + "\n")
            continue
        if command == "exit":
            print(handle_exit(skt))
            break
        feedback = commands[command](skt)
        print(feedback)


def main():
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("connecting to main server...")
    my_socket.connect(main_server_addr)
    print("connected to main server")

    wait_for_command(my_socket)
    # close connection
    my_socket.close()
    print("connection shut")


if __name__ == '__main__':
    main()
