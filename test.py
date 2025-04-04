import subprocess
import platform
import time

import psutil
import socket
import connect_protocol
import threading
import hashlib
import binascii


def get_main_interface_ip():
    # Get the default gateway (the one used to reach the internet)
    gateways = psutil.net_if_addrs()
    default_gateway = psutil.net_if_stats()

    # Find the interface with an active connection
    for interface, stats in default_gateway.items():
        if stats.isup and interface in gateways:  # Check if it's up and has addresses
            for addr in gateways[interface]:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    return addr.address  # Return the private IP

    return None  # No valid IP found


def backup_routes():
    with open("route_backup2.txt", "w") as f:
        if platform.system() == "Windows":
            result = subprocess.run("route print", capture_output=True, text=True, shell=True)
        else:
            result = subprocess.run("ip route", capture_output=True, text=True, shell=True)
        f.write(result.stdout)


def try_enc():
    msg = b"hello"
    key = b"blah" * 8
    data = connect_protocol.encrypt(msg, key)
    print(data)
    new_data = data.decode('latin-1')
    print(new_data)
    print(new_data.encode('utf-8'))
    print(new_data.encode('utf-8').decode('utf-8'))
    decr = connect_protocol.decrypt(new_data.encode('latin-1'), key)
    print(decr)
    ab = "hello"
    ab = ab.encode()
    print(ab.decode('latin-1'))
    ab = ab.decode('latin-1')
    print(ab.encode('latin-1'))

    key1 = 2 ** 224
    mod1 = connect_protocol.get_prime()
    k = pow(2, key1, mod1)
    print(k)


def create_server(ls):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 9123))
    server.listen(1)
    s, _ = server.accept()
    ls.append(s)
    key = connect_protocol.dh_send(s)
    ls.append(key)


def communicate_test():
    ls = list()
    t = threading.Thread(target=create_server, args=[ls])
    t.start()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 9123))
    print("client is connected")

    client_key = connect_protocol.dh_get(client)
    t.join()
    s, server_key = ls
    if server_key == client_key:
        # key = hashlib.sha256(server_key).digest()
        key = server_key
        print("key data:", len(server_key), key)

        msg = "你好世界"
        s.send(connect_protocol.create_msg(msg, "test", key))
        cmd, data = connect_protocol.get_msg(client, key)
        print(f"cmd: {cmd}\ndata: {data}\t {data == msg}")
    else:
        print("false")


# communicate_test()
"""
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print(s)
s.bind(("0.0.0.0", 1234))
if s:
    print("here:", s)
s.close()
print(s)


x = 300  # Binary: 100101100 (9 bits)
print(x.bit_length())  # 9 bits
print((x.bit_length() + 7) // 8)  # (9 + 7) // 8 = 2 bytes
print(x.to_bytes((x.bit_length() + 7) // 8, 'big'))  # b'\x01,' (2 bytes)
"""


def abc(a):
    print("1:", a)
    print("2:", threading.get_ident())
    if a is not None:
        print("3")


"""b = "a"
t = threading.Thread(target=abc, args=[b])
t.start()
print(4)"""

import adapter_conf
v_interface = adapter_conf.Adapter(ip='10.0.0.50', vpn_ip='10.0.0.21')


from scapy.arch.windows import get_windows_if_list

interfaces = get_windows_if_list()
name = v_interface.name

for iface in interfaces:
    print(iface)
    if name in iface['name']:
        print("here")


print("started 15 wait")
time.sleep(15)
print("stopped waiting")

import scapy_client

client = scapy_client.VPNClient(
        vpn_server_ip="10.0.0.21",
        #virtual_adapter_ip="10.0.0.50",
        virtual_adapter_ip=v_interface.ip,
        #virtual_adapter_name="wrgrd",
        virtual_adapter_name=v_interface.name,
        initial_vpn_port=5123,
        client_port=8800,
        private_ip="10.0.0.15"
    )

try:
    client.open_connection()
    # Keep main thread alive while connection is active
    while client.active:
        threading.Event().wait(1)
except KeyboardInterrupt:
    client.end_connection()
    v_interface.delete_adapter()
