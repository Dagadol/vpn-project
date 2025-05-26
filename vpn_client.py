import os
import random
import subprocess
import socket
import threading
import time
import ssl

import adapter_conf
import connect_protocol
import scapy_client
import queue
import gui_master


# Global state
vpn_client = None
v_interface = None
current_client_port = None
# current_private_ip = None

# Global variables
key = None
command_queue = queue.Queue()
client_handler = connect_protocol.CommandHandler()
vpn_gui = gui_master.AppGUI(cmd_q=command_queue, receiver=client_handler)

main_server_addr = ("10.0.0.17", 5500)  # main server connection
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.check_hostname = False  # We're connecting by IP
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations('server.crt')  # Trust this cert

adapter_conf.add_static_route(main_server_addr[0])  # create route exception


avail_commands = """
invalid command!
Connect: connect to best vpn server
Disconnect: disconnect from current vpn server
Change: change vpn server
Exit: shutdown application
Else: show list of commands
"""


def handle_logout(skt):
    if not handle_disconnect(skt, "logout"):
        # Notify server
        skt.send(connect_protocol.create_msg("i want to leave", "logout"))

    # --- Function to perform the login action in the GUI thread --- #
    def do_login_gui():
        vpn_gui.login()  # Now runs in correct thread

    # --- Function to perform clear and schedule login --- #
    def do_clear_and_schedule_login_gui():
        vpn_gui.clear_window()  # Now runs in correct thread
        vpn_gui.logged_in = False
        # Schedule the login() to run AFTER clear_window finishes
        vpn_gui.after(10, do_login_gui)  # Use small delay (10ms) or 0

    # --- Schedule the first step (clear) in the main GUI thread --- #
    vpn_gui.after(0, do_clear_and_schedule_login_gui)

    return True  # Indicate command was processed


def handle_exit(skt):
    global key
    print("[DEBUG] enter handle_exit")
    adapter_conf.remove_static_route(main_server_addr[0])  # remove route exception
    if not handle_disconnect(skt, "exit"):  # if disconnected

        # Notify server
        skt.send(connect_protocol.create_msg("i want to leave", "exit"))
    print("[DEBUG] server was notified")
    key = None
    return True


def handle_connect(skt) -> bool:
    global vpn_client, v_interface, current_client_port

    if vpn_client:
        print("Already connected")
        return True  # return True, meaning client is connected. but should not get here

    # Generate client port
    port = random.randint(50600, 54000)
    while str(port) in subprocess.run("netstat -n", capture_output=True, text=True, shell=True).stdout:
        port = random.randint(50600, 54000)

    country = vpn_gui.selected_country
    my_password1 = os.urandom(16).hex()
    my_password2 = os.urandom(16).hex()
    skt.send(connect_protocol.create_msg(f"{port}~{country}~{my_password1}~{my_password2}", "connect"))
    vpn_gui.logger.debug("sent to server request connect")

    cmd, msg = client_handler.get_thread_data(skt=skt, block=40)
    if cmd == "connect_0":
        print("Connection refused:", msg)
        vpn_gui.logger.info("Connection refused: " + msg)
        return False
    if cmd != "connect_1":
        print("Protocol error:", cmd, msg)
        vpn_gui.logger.error(f"Protocol error: {cmd} {msg}")
        return False

    # Parse server response
    vpn_ip, vpn_port, vm_ip, server_code, server_country = msg.split("~")
    vpn_gui.logger.debug(f"Connecting to country: {server_country}")

    try:
        # Create virtual adapter
        v_interface = adapter_conf.Adapter(gui=vpn_gui, ip=vm_ip, vpn_ip=vpn_ip)

        # ADD DELAY HERE (e.g., 15 seconds)
        print("adapter finished initializing")
        # time.sleep(10)  # Critical for OS to recognize the interface

        current_client_port = port

        # Create and start VPN client
        vpn_client = scapy_client.VPNClient(
            vpn_server_ip=vpn_ip,
            virtual_adapter_ip=vm_ip,
            virtual_adapter_name=v_interface.name,  # Ensure dynamic name
            initial_vpn_port=int(vpn_port),
            client_port=current_client_port,
            gui=vpn_gui
        )
        status = vpn_client.open_connection(server_code, my_password1, my_password2)
        if not status:
            return False
        return True
    except Exception as e:
        print("Connection failed:", e)  # maybe let server know that connection failed
        if v_interface:
            if vpn_client:
                handle_disconnect(skt)
            else:
                v_interface.delete_adapter()
                v_interface = None

        return False


def handle_disconnect(skt, cmd: str = "dconnect") -> bool:
    global vpn_client, v_interface, current_client_port

    vpn_gui.connected = False

    if not vpn_client:
        print("Already disconnected")
        if cmd == "dconnect":
            vpn_gui.logger.warning("Already disconnected")
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
    print("Disconnected successfully")
    if vpn_gui.active:
        vpn_gui.logger.debug("Disconnected successfully")
    return True


def handle_change(skt):
    global vpn_client, v_interface

    if not vpn_client:
        print("Not connected")
        vpn_gui.logger.warning("Not connected")
        return False

    # Request server change
    country = vpn_gui.selected_country
    my_password1 = os.urandom(16).hex()
    my_password2 = os.urandom(16).hex()
    skt.send(connect_protocol.create_msg(
        f"{vpn_client.vpn_ip}~{vpn_client.my_port}~{v_interface.ip}~{country}~{my_password1}~{my_password2}",
        "change"))
    cmd, msg = client_handler.get_thread_data(skt)

    vpn_gui.logger.debug("Change server request was sent to the server")

    if cmd == "change_0":
        print("Change failed:", msg)
        vpn_gui.logger.error(f"Change failed: {msg}")
        return False
    if cmd != "change_1":
        print("Protocol error:", cmd, msg)
        vpn_gui.logger.error(f"Protocol error: {cmd}, {msg}")
        return False

    # Parse new server details
    new_vpn_ip, new_vpn_port, new_vm_ip, server_code, server_country = msg.split("~")

    vpn_gui.logger.debug(f"Connecting to country: {server_country}")

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
            gui=vpn_gui
        )

        # Replace old connection
        vpn_client.end_connection()
        vpn_client = new_client
        status = vpn_client.open_connection(server_code, my_password1, my_password2)
        if not status:
            return False
        return True
    except Exception as e:
        print("Server change failed:", e)
        vpn_gui.logger.error(f"Server change failed: {e}")
        return False


def server_connection(skt):  # TODO: exchange keys in this function
    global key, command_queue
    # first connection:

    skt.send(connect_protocol.create_msg(f"from_id:{threading.get_native_id()}", "f_conn"))
    key = True  # for now
    # first connection has was closed
    while key:
        cmd, msg = client_handler.get_thread_data(skt, threading.get_native_id())
        if cmd == "shutdown":
            thread, msg, ip = msg.split("~")
            print(f"{msg}\tequal threads: {thread == f"to_id:{threading.get_native_id()}"}")

            vpn_gui.logger.warning("VPN server was shutdown, trying to change to another server")

            # check if client is still connected to current server
            if vpn_client:
                if ip == vpn_client.vpn_ip:
                    if command_queue.all_tasks_done:  # if no tasks in commands

                        # block GUI's buttons
                        gui_master.block_buttons(vpn_gui)
                        command_queue.put(("change", skt))
                    else:
                        vpn_gui.logger.critical("Unable to change server automatically")
                else:
                    print(f"fake/wrong IP: '{ip}' correct IP: '{vpn_client.vpn_ip}'")
                    vpn_gui.logger.warning(f"fake/wrong IP: '{ip}' correct IP: '{vpn_client.vpn_ip}'")


def refresh_countries(skt):
    skt.send(connect_protocol.create_msg("refresh", "countries"))
    cmd, msg = client_handler.get_thread_data(skt)
    if cmd != "countries":
        return False
    if vpn_gui.verified:
        if msg == "none":
            values = ["Any"]
        else:
            values = ["Any"] + msg.split("~")
        vpn_gui.country_menu.configure(values=values)


def show_queries(args):
    skt, filters = args
    print(f"my filters: {filters}")
    skt.send(connect_protocol.create_msg(filters, "admin"))
    cmd, msg = client_handler.get_thread_data(skt)
    if cmd != "admin":
        vpn_gui.logger.error(msg)
        return False
    elif msg == "no user was found":
        vpn_gui.logger.info(msg)
        return True

    query_results = gui_master.json.loads(msg)
    vpn_gui.display_users(query_results)

    return True


def handle_verify(args):
    def back_to_main():
        vpn_gui.main()

    def clear_window():
        vpn_gui.clear_window()
        vpn_gui.verified = True
        vpn_gui.after(10, back_to_main)

    # set variables
    error_label = [widget for widget in vpn_gui.winfo_children()  # get the error label in `verify context`
                   if isinstance(widget, gui_master.customtkinter.CTkLabel)][0]
    skt, req = args  # args got from the function

    # pass request to server
    skt.send(connect_protocol.create_msg(req, "verify"))
    cmd, msg = client_handler.get_thread_data(skt)
    if cmd != "verify":
        print(f"error receiving verify ack. cmd {cmd}, msg {msg}")
        error_label.configure(text=msg)
        return
    if "new" in req:  # case of new code request
        if msg == "true":
            error_label.configure(text="30 seconds before code expired\nenter code below", text_color="black")
        elif "mail" in msg:
            error_label.configure(text=msg, text_color="red")
        else:
            error_label.configure(text=f"wait {30 - int(float(msg))} seconds before asking again", text_color="red")
    else:  # case of try to verify request
        if msg == "true":
            vpn_gui.after(0, clear_window)
        elif msg == "exp":
            error_label.configure(text="code was expired")
        elif msg == "false":
            error_label.configure(text="code is not matching")
        elif msg == "email":
            error_label.configure(text_color="no email was set")  # shouldn't get here
        else:
            error_label.configure(text="no code was generated")


def handle_command_queue():
    global command_queue
    commands = {
        "connect": handle_connect,
        "disconnect": handle_disconnect,
        "change": handle_change,
        "exit": handle_exit,
        "logout": handle_logout,
        "refresh": refresh_countries,
        "admin": show_queries,
        "verify": handle_verify
    }
    while True:
        cmd, args = command_queue.get()
        print("current command:", cmd)

        if cmd == "connect":
            vpn_gui.connected = commands[cmd](args)

        if cmd != "connect":
            status = commands[cmd](args)

        if cmd == "change" and not status:
            vpn_gui.logger.warning("Failed changing server. Please consider disconnecting from the VPN")

        # block might be unnecessary
        if cmd == "exit":
            break

        command_queue.task_done()
        if cmd not in ["logout", "exit"]:
            vpn_gui.after(0, vpn_gui.unblock_buttons)


def wait_for_command_gui(skt):
    vpn_gui.socket = skt
    # vpn_gui.protocol("WM_DELETE_WINDOW", lambda: vpn_gui.on_close(vpn_client))
    vpn_gui.login()
    vpn_gui.mainloop()            # <-- returns as soon as destroy() is called
    vpn_gui.active = False
    print("left program")


def main():
    global key
    with socket.create_connection(main_server_addr) as skt:
        secure_skt = context.wrap_socket(skt, server_hostname=main_server_addr[0])
        print("Connected to main server")

        t_wait = threading.Thread(target=server_connection, args=[secure_skt], daemon=True)
        t_wait.start()

        while not key:
            time.sleep(0.1)

        t_listen = threading.Thread(target=client_handler.listen_for_commands, args=[secure_skt])
        t_listen.start()
        t_command_handler = threading.Thread(target=handle_command_queue)  # maybe set as a daemon
        t_command_handler.start()

        wait_for_command_gui(secure_skt)

        t_command_handler.join()
        print("all task are done")

        client_handler.turn_off()
        t_listen.join()

        secure_skt.close()
    print("Connection closed")


if __name__ == '__main__':
    main()
