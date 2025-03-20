import os
import base64
import time
import atexit


def check_interface_exists(name):
    """Check if a network interface exists by name."""
    return os.system(f"netsh interface show interface \"{name}\"") == 0  # does exist


class Connection:
    def __init__(self, vpn_ip, vpn_port, my_port, my_ip):
        self.vpn_ip = vpn_ip
        self.vpn_port = vpn_port
        self.my_port = my_port
        self.private_ip = my_ip
        self.active = False


class Adapter:
    def __init__(self, ip: str = ""):
        self.ip = ip
        self.__name = "jonathanVPN"
        self.__num = 1
        self.__config_adapter()
        atexit.register(self.delete_adapter)

    def name(self):
        return self.__name

    def update_ip(self, ip: str = ""):
        if ip:
            self.ip = ip
        os.system(f"netsh interface set interface name=\"{self.__name}\" enabled")
        os.system(f"netsh interface ip set address \"{self.__name}\" static {self.ip} 255.255.255.0")
        os.system(f"netsh interface ip set route 0.0.0.0/0 \"{self.__name}\" {self.ip} 0 1")
        os.system(f"netsh interface ip set interface \"{self.__name}\" metric=1")

    def __update_name(self):
        self.__num += 1
        self.__name = f"{self.__name.split(" ")[0]} {self.__num}"

    def __create_wireguard_adapter(self):  # private method
        """Create a WireGuard adapter by installing a tunnel service with a minimal config."""
        # generate a random private key
        private_key = base64.b64encode(os.urandom(32)).decode('utf-8')

        # create minimal wireguard configuration
        config_content = f"""
        [Interface]
        PrivateKey = {private_key}
        """
        file_name = f"{self.__name}.conf"

        try:
            with open(file_name, "w") as f:
                f.write(config_content)

            # Get the directory of the current script
            script_dir = os.path.dirname(os.path.abspath(__file__))

            # Combine the script directory with the filename to get the full path
            file_path = os.path.join(script_dir, file_name)

            # install the tunnel service (requires WireGuard to be installed)
            os.system(f"wireguard.exe /installtunnelservice \"{file_path}\"")

            time.sleep(3)  # allow time for interface creation
        finally:
            # can delete temp file, because wireguard saves it
            if os.path.exists(file_name):
                os.remove(file_name)

    def __config_adapter(self):
        while check_interface_exists(self.__name):  # if adapter with this name exists
            self.__update_name()  # rename adapter

        self.__create_wireguard_adapter()  # create new adapter
        if self.ip:
            os.system(f"netsh interface set interface name=\"{self.__name}\" enabled")
            os.system(f"netsh interface ip set address \"{self.__name}\" static {self.ip} 255.255.255.0")
            os.system(f"netsh interface ip set route 0.0.0.0/0 \"{self.__name}\" {self.ip} 0 1")
            os.system(f"netsh interface ip set interface \"{self.__name}\" metric=1")

        print("adapter is up and running")

    def delete_adapter(self):
        if check_interface_exists(self.__name):
            os.system(f"netsh interface set interface \"{self.__name}\" disable")
            os.system(f"wireguard.exe /uninstalltunnelservice \"{self.__name}\"")

            print("adapter was removed")
        else:
            print("adapter does not exist")
