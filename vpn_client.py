import random
import subprocess
import socket
import threading
import time

import adapter_conf
import connect_protocol
from scapy_client import VPNClient
import queue

# Global state
vpn_client = None
v_interface = None
current_client_port = None
current_private_ip = None
main_server_addr = ("10.0.0.20", 5500)
adapter_conf.add_static_route(main_server_addr[0])  # create route exception

key = None
command_queue = queue.Queue()

avail_commands = """
invalid command!
Connect: connect to best vpn server
Disconnect: disconnect from current vpn server
Change: change vpn server
Exit: shutdown application
Else: show list of commands
"""


def block_until_finished_task() -> None:
    global command_queue

    i = command_queue.unfinished_tasks
    while True:
        if command_queue.unfinished_tasks < i:
            return None
        i = command_queue.unfinished_tasks
        time.sleep(0.01)


def handle_exit(skt):
    if not handle_disconnect(skt, "exit"):  # if disconnected

        # Notify server
        skt.send(connect_protocol.create_msg("i want to leave", "exit"))

    adapter_conf.remove_static_route(main_server_addr[0])  # remove route exception

    return True


def handle_connect(skt):
    global vpn_client, v_interface, current_client_port, current_private_ip

    if vpn_client:
        print("Already connected")
        return False

    # Generate client port
    port = random.randint(50600, 54000)
    while port in subprocess.run("netstat -n", capture_output=True, text=True, shell=True).stdout:
        port = random.randint(50600, 54000)

    skt.send(connect_protocol.create_msg(str(port), "connect"))
    cmd, msg = client_handler.get_thread_data(skt)

    if cmd == "connect_0":
        print("Connection refused:", msg)
        return False
    if cmd != "connect_1":
        print("Protocol error:", cmd, msg)
        return False

    # Parse server response
    vpn_ip, vpn_port, vm_ip, my_ip = msg.split("~")

    try:
        # Create virtual adapter
        v_interface = adapter_conf.Adapter(ip=vm_ip, vpn_ip=vpn_ip)

        current_client_port = port
        current_private_ip = my_ip

        # Create and start VPN client
        vpn_client = VPNClient(
            vpn_server_ip=vpn_ip,
            virtual_adapter_ip=vm_ip,
            virtual_adapter_name=v_interface.name,
            initial_vpn_port=int(vpn_port),
            client_port=current_client_port,
            private_ip=current_private_ip
        )
        vpn_client.open_connection()
        return True
    except Exception as e:
        print("Connection failed:", e)
        if v_interface:
            v_interface.delete_adapter()
            v_interface = None
        return False


def handle_disconnect(skt, cmd: str = "dconnect"):
    global vpn_client, v_interface, current_client_port, current_private_ip

    if not vpn_client:
        print("Already disconnected")
        return False

    # Notify server
    skt.send(connect_protocol.create_msg(
        f"{vpn_client.vpn_ip}~{v_interface.ip}", cmd  # data "important" for the server
    ))

    # Clean up client
    vpn_client.end_connection()
    vpn_client = None

    # Remove adapter
    v_interface.delete_adapter()
    v_interface = None

    current_client_port = None
    current_private_ip = None
    print("Disconnected successfully")
    return True


def handle_change(skt):
    global vpn_client, v_interface

    if not vpn_client:
        print("Not connected")
        return False

    # Request server change
    skt.send(connect_protocol.create_msg(
        f"{vpn_client.vpn_ip}~{vpn_client.my_port}~{v_interface.ip}", "change"
    ))
    cmd, msg = client_handler.get_thread_data(skt)

    if cmd == "change_0":
        print("Change failed:", msg)
        return False
    if cmd != "change_1":
        print("Protocol error:", cmd, msg)
        return False

    # Parse new server details
    new_vpn_ip, new_vpn_port, new_vm_ip = msg.split("~")

    try:
        # Update virtual adapter
        v_interface.assign_ip(new_vm_ip)
        v_interface.assign_new_vpn(new_vpn_ip)

        # Create new VPN client
        new_client = VPNClient(
            vpn_server_ip=new_vpn_ip,
            virtual_adapter_ip=new_vm_ip,
            virtual_adapter_name=v_interface.name,
            initial_vpn_port=int(new_vpn_port),
            client_port=current_client_port,
            private_ip=current_private_ip
        )

        # Replace old connection
        vpn_client.end_connection()
        vpn_client = new_client
        vpn_client.open_connection()
        return True
    except Exception as e:
        print("Server change failed:", e)
        return False


def server_connection(skt):  # TODO: exchange keys in this function
    global key
    # first connection:

    skt.send(connect_protocol.create_msg(f"from_id:{threading.get_native_id()}", "f_conn"))
    # first connection has was closed
    while True:
        cmd, msg = client_handler.get_thread_data(skt, threading.get_native_id())
        if cmd == "shutdown":
            thread, msg, ip = msg.split("~")
            print(f"{msg}\tequal threads: {thread == thread.get_native_id()}")
            if vpn_client:
                if ip == vpn_client.vpn_server_ip:
                    command_queue.put("change", skt)


def handle_command_queue():
    global command_queue
    commands = {
        "connect": handle_connect,
        "disconnect": handle_disconnect,
        "change": handle_change,
        "exit": handle_exit
    }
    while True:
        cmd, args = command_queue.get()
        commands[cmd](args)
        command_queue.task_done()
        # block might be unnecessary
        block_until_finished_task()
        if cmd == "exit":
            break


def wait_for_command(skt):
    commands = {
        "connect": handle_connect,
        "disconnect": handle_disconnect,
        "change": handle_change,
        "exit": handle_exit
    }

    while True:
        command = input("Enter command: ").lower()
        if command not in commands:
            print(avail_commands)
            continue

        if command == "exit":
            # commands[command](skt)
            command_queue.put(command, skt)
            break
        """
        success = commands[command](skt)
        print("Success" if success else "Failed")
        """
        command_queue.put(command, skt)


client_handler = connect_protocol.CommandHandler()


def main():
    global key
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as skt:
        skt.connect(main_server_addr)
        print("Connected to main server")

        t_wait = threading.Thread(target=server_connection, args=[skt])
        t_wait.start()

        while not key:
            time.sleep(0.1)

        threading.Thread(target=client_handler.listen_for_commands, args=[skt]).start()
        t_command_handler = threading.Thread(target=handle_command_queue)  # maybe set as a daemon
        t_command_handler.start()

        threading.Thread(target=wait_for_command, args=[skt]).run()
        t_wait.join()
        client_handler.turn_off()
        # wait_for_command(skt)

    client_handler.turn_off()
    print("Connection closed")


if __name__ == '__main__':
    main()
