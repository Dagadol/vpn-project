import os
import base64
import subprocess
import time
import netifaces
from scapy.arch.windows import get_windows_if_list


def get_index_scapy(name="wrgrd"):
    interfaces = get_windows_if_list()
    # name = "wrgrd"

    for iface in interfaces:
        if iface["name"] == name:
            return iface["index"]
    return None


def get_default_gateway_grok():
    # Step 1: Get the default gateway and interface GUID
    gateways = netifaces.gateways()
    default_gateway, interface_guid = gateways['default'][netifaces.AF_INET][:2]

    # Step 2: Get the IP address of the interface
    ip_addresses = netifaces.ifaddresses(interface_guid).get(netifaces.AF_INET, [])
    if not ip_addresses:
        print("No IPv4 address found for the interface")
        exit(1)
    ip_address = ip_addresses[0]['addr']

    # Step 3: Run netsh interface ip show config to map IP to friendly interface name
    config_output = subprocess.check_output('netsh interface ip show config', shell=True).decode()
    lines = config_output.splitlines()
    ip_to_name = {}
    current_name = None
    for line in lines:
        if line.startswith('Configuration for interface "'):
            # Extract the interface name between quotes
            start = line.find('"') + 1
            end = line.find('"', start)
            current_name = line[start:end]
        elif line.strip().startswith('IP Address:'):
            # Extract the IP address
            ip = line.split(':')[1].strip()
            if current_name:
                ip_to_name[ip] = current_name

    # Find the friendly interface name using the IP address
    interface_name = ip_to_name.get(ip_address)
    if not interface_name:
        print(f"No interface found with IP address {ip_address}")
        exit(1)

    # Step 4: Run netsh interface ipv4 show interfaces to get interface indices
    output = subprocess.check_output('netsh interface ipv4 show interfaces', shell=True).decode()
    lines = output.splitlines()
    interface_map = {}
    for line in lines:
        if line.strip() and not line.startswith('Idx'):
            parts = line.split()
            if len(parts) >= 5:
                idx = parts[0]
                name = ' '.join(parts[4:])
                interface_map[name] = idx

    # Step 5: Get the index for the interface
    interface_index = interface_map.get(interface_name)
    if interface_index:
        print(f"Default Gateway: {default_gateway}")
        print(f"Interface Index: {interface_index}")
        return default_gateway, interface_index
    else:
        print(f"Interface '{interface_name}' not found in netsh interface list")
        return None, None


def get_interface_index(interface_name):
    result = subprocess.run(
        ['netsh', 'interface', 'ip', 'show', 'interface'],
        capture_output=True,
        text=True,
        encoding='utf-8'  # Force UTF-8 decoding
    )
    # print("results:", result)
    lines = result.stdout.splitlines()

    for line in lines:
        if interface_name in line:
            parts = line.split()
            return parts[0]  # The first column is the index

    return None  # If not found


def add_static_route(static_ip):
    gateway_ip, default_interface_index = get_default_gateway_grok()
    if gateway_ip and default_interface_index:
        print(f"adding a static route to IP at: '{static_ip}'")
        subprocess.run(
            ['route', 'add', static_ip, 'mask', '255.255.255.255', gateway_ip, 'if',
             str(default_interface_index)],
            check=True
        )
    else:
        print("Warning: Could not determine the default gateway or interface index.")


def remove_static_route(static_ip):
    gateway_ip, default_interface_index = get_default_gateway_grok()
    if gateway_ip and default_interface_index:
        print(f"removing static route: '{static_ip}'")
        subprocess.run(
            ['route', 'delete', static_ip, 'mask', '255.255.255.255', gateway_ip, 'if',
             str(default_interface_index)],
            check=True
        )
    else:
        print("Warning: Could not determine the default gateway or interface index.")


def interface_exists(name):
    """Check if an interface with the given name exists."""
    result = subprocess.run(
        ['netsh', 'interface', 'show', 'interface'],
        capture_output=True,
        text=True,
        encoding='utf-8'
    )
    return name in result.stdout


class Adapter:
    def __init__(self, ip: str = "", vpn_ip=""):
        self.ip = ip
        self.vpn_ip = vpn_ip
        self.base_name = "wrgrd"  # once was 'jjj' and 'jonathanVPN'
        self.name = self.get_available_name()

        # Ensure WireGuard is installed
        self.wireguard_path = r'C:\Program Files\WireGuard\wireguard.exe'
        if not os.path.exists(self.wireguard_path):
            raise FileNotFoundError("WireGuard is not installed at the expected path.")

        self.setup_adapter()

    def get_available_name(self):
        """Finds an available adapter name by appending numbers to the base name."""
        num = 0
        while interface_exists(self.base_name if num == 0 else f"{self.base_name}_{num}"):
            num += 1
        return self.base_name if num == 0 else f"{self.base_name}_{num}"

    def setup_adapter(self):
        """Main function to set up the WireGuard adapter with the correct configurations."""
        print("Checking existing interface...")
        if interface_exists(self.name):
            print(f"Interface '{self.name}' already exists. Removing it first.")
            self.delete_adapter()
            time.sleep(2)  # Allow time for removal

        self.create_wireguard_adapter()
        # Time delay is considered inside the function

        print("Assigning static IP...")
        self.assign_ip()
        time.sleep(1)  # Allow time for IP configuration

        print("Configuring routing...")
        self.configure_routes()

        time.sleep(10)
        print(f"Adapter '{self.name}' is up and running.")

    def create_wireguard_adapter(self):
        """Creates a WireGuard virtual adapter with a minimal config."""
        private_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        config_content = f"""
        [Interface]
        PrivateKey = {private_key}
        """

        file_name = f"{self.name}.conf"
        with open(file_name, "w") as f:
            f.write(config_content)

        file_path = os.path.abspath(file_name)
        print("path:", file_path)

        print("file was created")

        try:
            subprocess.run([self.wireguard_path, '/installtunnelservice', file_path], check=True)
            print("wait 5 seconds")
            time.sleep(5)
            print(f"WireGuard adapter '{self.name}' installed successfully.")

        finally:
            os.remove(file_name)

    def assign_ip(self, ip=""):
        """Assigns a static IP address to the virtual adapter."""
        if ip:
            self.ip = ip
            print("new virtual IP:", ip)

        print("name:", self.name)
        subprocess.run(
            ['netsh', 'interface', 'ip', 'set', 'address', self.name, 'static', self.ip, '255.255.255.0'],
            check=True
        )

    def assign_new_vpn(self, vpn_ip):
        remove_static_route(self.vpn_ip)  # removing old VPN route

        self.vpn_ip = vpn_ip  # assign the new vpn ip into the public variable
        add_static_route(self.vpn_ip)  # create new route to the new VPN

    def configure_routes(self):
        """Configures routing rules for the virtual adapter."""
        interface_index = get_index_scapy(self.name)
        if interface_index is None:
            print("Error: Could not find interface index. Routing setup aborted.")
            return

        subprocess.run(
            ['route', 'add', '0.0.0.0', 'mask', '0.0.0.0', self.ip, 'if', str(interface_index)],
            check=True
        )

        if self.vpn_ip:
            add_static_route(self.vpn_ip)

    def delete_adapter(self):
        """Removes the WireGuard virtual adapter."""
        subprocess.run([self.wireguard_path, "/uninstalltunnelservice", self.name], check=True)
        print(f"WireGuard adapter '{self.name}' removed.")
        if self.vpn_ip:
            remove_static_route(self.vpn_ip)


# Test
if __name__ == "__main__":
    print("creating the adapter")
    adapter = Adapter(ip="10.0.0.50", vpn_ip="10.0.0.21")
