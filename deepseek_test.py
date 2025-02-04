import socket
import asyncio

# Client Configuration
VIRTUAL_ADAPTER_IP = "10.0.0.50"


def filter_adapter(packet: bytes, is_source: bool) -> bool:
    virtual_ip_bytes = socket.inet_aton(VIRTUAL_ADAPTER_IP)
    dest_ip = packet[16:20]
    # Block packets targeting the virtual adapter (loop prevention)
    if not is_source and dest_ip == virtual_ip_bytes:
        return False
    return True


async def handle_server_packets(client_socket, recv):
    loop = asyncio.get_event_loop()
    while True:
        data = await recv.get()
        await loop.sock_sendall(client_socket, data)


async def handle_adapter_packets(client_socket, send):
    loop = asyncio.get_event_loop()
    while True:
        data, addr = await loop.sock_recvfrom(client_socket, 65565)
        if filter_adapter(data, True):
            await send.put(data)


async def client_main(send, recv):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    client_socket.bind((VIRTUAL_ADAPTER_IP, 0))
    client_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    await asyncio.gather(
        handle_adapter_packets(client_socket, send),
        handle_server_packets(client_socket, recv)
    )


async def forward_to_internet(server_socket, recv):
    loop = asyncio.get_event_loop()
    while True:
        data = await recv.get()
        await loop.sock_sendall(server_socket, data)


async def internet_recv(server_socket, send):
    loop = asyncio.get_event_loop()
    while True:
        data, addr = await loop.sock_recvfrom(server_socket, 65565)
        print("ip dest:", data[16:20], flush=True)
        if filter_adapter(data, False):
            await send.put(data)


async def server_main(recv, send):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    server_socket.bind(("0.0.0.0", 0))
    server_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    await asyncio.gather(
        forward_to_internet(server_socket, recv),
        internet_recv(server_socket, send)
    )


async def main():
    forward_to_server = asyncio.Queue()
    forward_to_client = asyncio.Queue()
    try:
        await asyncio.gather(
            server_main(forward_to_server, forward_to_client),
            client_main(forward_to_server, forward_to_client)
        )
    except KeyboardInterrupt:
        print("\nExiting gracefully...")


if __name__ == "__main__":
    asyncio.run(main())
