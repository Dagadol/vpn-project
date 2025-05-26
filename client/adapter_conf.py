import os
import subprocess
import time
import netifaces
from scapy.arch.windows import get_windows_if_list

import gui_master


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
    config_output = subprocess.check_output('netsh interface ip show config', shell=True)
    lines = config_output.splitlines()
    ip_to_name = {}
    current_name = None
    for line in lines:
        if line.startswith(b'Configuration for interface "'):
            # Extract the interface name between quotes
            start = line.find(b'"') + 1
            end = line.find(b'"', start)
            current_name = line[start:end]
        elif line.strip().startswith(b'IP Address:'):
            # Extract the IP address
            ip = line.split(b':')[1].strip().decode()
            if current_name:
                ip_to_name[ip] = current_name

    # Find the friendly interface name using the IP address
    interface_name = ip_to_name.get(ip_address)
    if not interface_name:
        print(f"No interface found with IP address {ip_address}")
        exit(1)

    # Step 4: Run netsh interface ipv4 show interfaces to get interface indices
    output = subprocess.check_output('netsh interface ipv4 show interfaces', shell=True)
    lines = output.splitlines()
    interface_map = {}
    for line in lines:
        if line.strip() and not line.startswith(b'Idx'):
            parts = line.split()
            if len(parts) >= 5:
                idx = parts[0]
                name = b' '.join(parts[4:])
                interface_map[name] = idx

    # Step 5: Get the index for the interface
    interface_index = interface_map.get(interface_name)
    if interface_index:
        print(f"Default Gateway: {default_gateway}")
        print(f"Interface Index: {interface_index}")
        return default_gateway, interface_index.decode()
    else:
        print(f"Interface '{interface_name}' not found in netsh interface list")
        return None, None


def get_physical_private_ip():
    default_guid = netifaces.gateways()["default"][netifaces.AF_INET][1]
    private_ip = netifaces.ifaddresses(default_guid)[netifaces.AF_INET][0]["addr"]
    return private_ip


def add_static_route(dest_ip: str, gui=None, cmd: str = "add"):
    """
    Add a /32 route for dest_ip.  If a ZeroTier interface exists,
    route via that interface (treating the local ZT IP as gateway).
    Otherwise use the system default gateway.
    """
    if gui:
        if not gui.active:  # meaning user chose to exit program
            gui = False

    gw_ip, iface_index = get_default_gateway_grok()
    if gui:
        gui.logger.info(f"Routing {dest_ip} via default gateway {gw_ip} (interface index {iface_index}).")

    # Install the static route
    subprocess.run([
        'route', cmd, dest_ip,
        'mask', '255.255.255.255',
        gw_ip,
        'if', str(iface_index)
    ], check=True)


def remove_static_route(static_ip, gui=None):
    """if
    gateway_ip, default_interface_index = get_default_gateway_grok()
    if gateway_ip and default_interface_index:
        print(f"removing static route: '{static_ip}'")
        subprocess.run(
            ['route', 'delete', static_ip, 'mask', '255.255.255.255', gateway_ip, 'if',
             str(default_interface_index)],
            check=True
        )
        return True
    else:
        print("Warning: Could not determine the default gateway or interface index.")"""
    add_static_route(dest_ip=static_ip, cmd="delete", gui=gui)


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
    def __init__(self, gui: gui_master.AppGUI | None = None, ip: str = "", vpn_ip=""):
        self.gui = gui
        self.ip = ip
        self.vpn_ip = vpn_ip
        self.base_name = "wrgrd"  # once was 'jjj' and 'jonathanVPN'
        self.name = self.get_available_name()

        # Ensure WireGuard is installed
        self.wireguard_path = r'C:\Program Files\WireGuard\wireguard.exe'
        if not os.path.exists(self.wireguard_path):
            if self.gui:
                self.gui.logger.critical("WireGuard is not installed at the expected path.")
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
            print(f"Interface '{self.name}' already exists. Removing it first.")  # shouldn't get here
            if self.gui:
                self.gui.logger.warning(f"Interface '{self.name}' already exists. Removing it first.")
            self.delete_adapter()
            time.sleep(2)  # Allow time for removal

        self.create_wireguard_adapter()
        # Time delay is considered inside the function

        print("Assigning static IP...")
        if self.gui:
            self.gui.logger.debug("Assigning static IP...")
        self.assign_ip()
        time.sleep(1)  # Allow time for IP configuration

        print("Configuring routing...")
        if self.gui:
            self.gui.logger.debug("Configuring routing...")
        self.configure_routes()
        print(f"Adapter '{self.name}' is up and running.")
        if self.gui:
            self.gui.logger.debug(f"Adapter '{self.name}' is up and running.")

        try:
            print("waiting 3 seconds for scapy to notice")
            if self.gui:
                self.gui.logger.debug("waiting 3 seconds for scapy to notice")
            time.sleep(1)
        except KeyboardInterrupt:
            print("keyboard Interrupt, closing adapter")
            self.delete_adapter()
            exit()

    def create_wireguard_adapter(self):
        """Creates a WireGuard virtual adapter with a minimal config."""
        # private_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        # key should always be the same, so new profiles won't be created
        config_content = f"""
        [Interface]
        PrivateKey = uOrpz7IW4imxN/CSDfdyN97s4f7tJSF514PFZ9LBNXY=
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
            if self.gui:
                self.gui.logger.debug("waiting 5 seconds for Windows to notice")
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
        if self.gui:
            self.gui.logger.debug(f"Updating new VPN route")
        remove_static_route(self.vpn_ip)  # removing old VPN route

        self.vpn_ip = vpn_ip  # assign the new vpn ip into the public variable
        add_static_route(self.vpn_ip, self.gui)  # create new route to the new VPN
        if self.gui:
            self.gui.logger.debug(f"Finished updating new VPN route")

    def configure_routes(self):
        """Configures routing rules for the virtual adapter."""
        interface_index = get_index_scapy(self.name)
        if interface_index is None:
            print("Error: Could not find interface index. Routing setup aborted.")
            if self.gui:
                self.gui.logger.error("Could not find interface index. Routing setup aborted.")
            return

        subprocess.run(
            ['route', 'add', '0.0.0.0', 'mask', '0.0.0.0', self.ip, 'if', str(interface_index)],
            check=True
        )

        if self.vpn_ip:
            add_static_route(self.vpn_ip, self.gui)

    def delete_adapter(self):
        """Removes the WireGuard virtual adapter."""
        subprocess.run([self.wireguard_path, "/uninstalltunnelservice", self.name], check=True)
        print(f"WireGuard adapter '{self.name}' was deleted.")
        if self.gui.active:
            self.gui.logger.debug(f"WireGuard adapter '{self.name}' was deleted.")
        if self.vpn_ip:
            remove_static_route(self.vpn_ip, self.gui)


# Test
if __name__ == "__main__":
    print("creating the adapter")
    adapter = Adapter(ip="10.2.0.1", vpn_ip="172.29.149.44")