import socket
import asyncio


# This code is a simplified vpn tunnel between client and server in a one code
# where the server in the same computer as the client, making it not really a vpn
# its purpose is not to be a real vpn but to test my understanding
async def main():
    # act as the connection between the client and server; simplified, no udp, no encryption
    forward_to_server = asyncio.Queue()
    forward_to_client = asyncio.Queue()

    try:
        await asyncio.gather(
            server_main(forward_to_server, forward_to_client),
            client_main(forward_to_server, forward_to_client)
        )
    except KeyboardInterrupt:
        print("\nExiting...")


# DeepSeek
def filter_adapter(packet: bytes) -> bool:
    """
    Determine if the packet's destination IP matches the adapter's IP.

    :param packet: Raw IPv4 packet bytes.
    :return: True if the specified IP matches the adapter's IP, False otherwise.
    """
    global VIRTUAL_ADAPTER_IP  # Assumed to be a string like "1.2.3.4"

    # Convert adapter IP to bytes (4-byte packed format)
    adapter_ip_bytes = socket.inet_aton(VIRTUAL_ADAPTER_IP)

    # Ensure packet is large enough to contain IP headers
    if len(packet) < 20:
        return False

    # Extract relevant IP portion based on check type
    packet_ip = packet[16:20]  # Destination IP offset in IPv4 header

    return packet_ip == adapter_ip_bytes


# Client
VIRTUAL_ADAPTER_IP = "10.0.0.50"


# get the data from the "server" and send it to the adapter to process the internet
async def handle_server_packets(client_socket: socket.socket, recv):  # not sure if this is the correct socket
    """

    :param client_socket: client socket
    :param recv: a queue in type of asyncio.Queue, simulate tunnel between server and client
    :return:
    """
    while True:
        # receive data from the VPN server
        data = await recv.get()

        # no need to change IP nor port, because in this simulation IP or port didn't change at all

        # if there is a problem it may be here fixme
        # client sends the data to himself essentially, if the the data's dest target is the virtual adapter
        # because the client's socket is bind to the virtual adapter's ip
        # again if there is a problem in the code it most likely to be here
        print("it is got here actually:", data[16:20].decode(), flush=True)
        client_socket.send(data)


async def handle_adapter_packets(client_socket, send):
    while True:
        data, _ = client_socket.recvfrom(65565)
        if not filter_adapter(data):  # take data if the destination is not the adapter's
            # send to the VPN server
            await send.put(data)


async def client_main(send, recv):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    client_socket.bind((VIRTUAL_ADAPTER_IP, 0))
    client_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    await asyncio.gather(handle_adapter_packets(client_socket, send), handle_server_packets(client_socket, recv))


# Server

async def forward_to_internet(server_socket, recv):
    while True:
        data = await recv.get()

        server_socket.send(data)


async def internet_recv(server_socket, send):
    while True:
        data, _ = server_socket.recvfrom(65565)
        print("ip dest:",  data[16:20], flush=True)

        if filter_adapter(data):  # true if packet's destination is the adapter's ip
            # usually IP addr dest is needed to change to the adapter
            # although in this simplified version it is being "cancelled out"
            # since we initially didn't change the source addr when we sent

            # send to the client
            await send.put(data)


async def server_main(recv, send):
    # bind socket to 0.0.0.0 to receive information from internet that are sent to the computer.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    server_socket.bind(("0.0.0.0", 0))
    server_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    await asyncio.gather(forward_to_internet(server_socket, recv), internet_recv(server_socket, send))


if __name__ == "__main__":
    asyncio.run(main())
