import random
import subprocess
import socket
import threading
import time

import adapter_conf
import connect_protocol
import scapy_client
import queue
import gui_master


# Global state
vpn_client = None
v_interface = None
current_client_port = None
current_private_ip = None
main_server_addr = ("10.0.0.10", 5500)
adapter_conf.add_static_route(main_server_addr[0])  # create route exception

key = None
command_queue = queue.Queue()
client_handler = connect_protocol.CommandHandler()
vpn_gui = gui_master.AppGUI(cmd_q=command_queue, receiver=client_handler)


avail_commands = """
invalid command!
Connect: connect to best vpn server
Disconnect: disconnect from current vpn server
Change: change vpn server
Exit: shutdown application
Else: show list of commands
"""


def block_until_finished_task() -> str:
    global command_queue
    i = command_queue.unfinished_tasks
    if not i:
        return "queue is empty"

    while True:
        if command_queue.unfinished_tasks < i:
            return "last task was finished"
        i = command_queue.unfinished_tasks
        time.sleep(0.01)


def handle_logout(skt):
    if not handle_disconnect(skt, "logout"):

        # Notify server
        skt.send(connect_protocol.create_msg("i want to leave", "logout"))

    print("start clear")
    vpn_gui.clear_window()
    print("end clear")

    vpn_gui.login()
    return True


def handle_exit(skt):
    global key
    if not handle_disconnect(skt, "exit"):  # if disconnected

        # Notify server
        skt.send(connect_protocol.create_msg("i want to leave", "exit"))

    adapter_conf.remove_static_route(main_server_addr[0])  # remove route exception
    key = None
    return True


def handle_connect(skt) -> bool:
    global vpn_client, v_interface, current_client_port, current_private_ip

    if vpn_client:
        print("Already connected")
        return True  # return True, meaning client is connected. but should not get here

    # Generate client port
    port = random.randint(50600, 54000)
    while str(port) in subprocess.run("netstat -n", capture_output=True, text=True, shell=True).stdout:
        port = random.randint(50600, 54000)

    skt.send(connect_protocol.create_msg(str(port), "connect"))
    print("sent to server request")

    cmd, msg = client_handler.get_thread_data(skt=skt, block=40)
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

        # ADD DELAY HERE (e.g., 15 seconds)
        print("adapter finished initializing")
        # time.sleep(10)  # Critical for OS to recognize the interface

        current_client_port = port
        current_private_ip = my_ip

        # Create and start VPN client
        vpn_client = scapy_client.VPNClient(
            vpn_server_ip=vpn_ip,
            virtual_adapter_ip=vm_ip,
            virtual_adapter_name=v_interface.name,  # Ensure dynamic name
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


def handle_disconnect(skt, cmd: str = "dconnect") -> bool:
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
        new_client = scapy_client.VPNClient(
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
    key = True  # for now
    # first connection has was closed
    while key:
        cmd, msg = client_handler.get_thread_data(skt, threading.get_native_id())
        if cmd == "shutdown":
            thread, msg, ip = msg.split("~")
            print(f"{msg}\tequal threads: {thread == thread.get_native_id()}")

            # check if client is still connected to current server
            if vpn_client:
                if ip == vpn_client.vpn_server_ip:
                    if command_queue.all_tasks_done:  # if no tasks in commands
                        command_queue.put(("change", skt))

                        # block GUI's buttons
                        gui_master.block_buttons(vpn_gui)


def handle_command_queue():
    global command_queue
    commands = {
        "connect": handle_connect,
        "disconnect": handle_disconnect,
        "change": handle_change,
        "exit": handle_exit,
        "logout": handle_logout
    }
    while True:
        cmd, args = command_queue.get()
        print("current command:", cmd)
        if cmd == "disconnect":
            vpn_gui.connected = False
        elif cmd == "connect":
            vpn_gui.connected = commands[cmd](args)

        if cmd != "connect":
            commands[cmd](args)

        # block might be unnecessary
        if cmd == "exit":
            break

        command_queue.task_done()
        vpn_gui.unblock_buttons()


def wait_for_command_gui(skt):
    vpn_gui.socket = skt
    vpn_gui.login()
    vpn_gui.mainloop()
    print("left program")
    command_queue.put(("exit", skt))


def main():
    global key
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as skt:
        skt.connect(main_server_addr)
        # skt.settimeout(10)
        print("Connected to main server")

        t_wait = threading.Thread(target=server_connection, args=[skt])
        t_wait.start()

        while not key:
            time.sleep(0.1)

        threading.Thread(target=client_handler.listen_for_commands, args=[skt]).start()
        t_command_handler = threading.Thread(target=handle_command_queue)  # maybe set as a daemon
        t_command_handler.start()

        wait_for_command_gui(skt)

        client_handler.turn_off()
        t_wait.join()

    print("Connection closed")


if __name__ == '__main__':
    main()
