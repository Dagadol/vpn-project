import socket
import os
import subprocess

og_gateway_ip = "10.0.0.138"
vpn_server_ip = ""
# Set virtual adapter
VIRTUAL_ADAPTER_IP = ""
virtual_adapter_name = "VPN client virtual adapter"

# Set default gateway to the virtual adapter

# Set virtual adapter's gateway to the adapter/vpn server


# Connect via an SSL to VPN server (for now), and get private key for an AES symmetric encryption
def first_connection() -> str:
    """

    :return: AES key from the server
    """
    pass


# Bind raw socket and create a UDP socket

# Receive packets from the adapter

# Encrypt packets (optional)

# Forward to the vpn server in UDP tunnel


# Receive the UDP packets from the VPN server
"""
Idea: add a range that packets must have at the start for a simple validation; could be before and after the encryption 
-Update the range every packet
"""
# Decrypt the data

# Forward the packets to the virtual adapter?
