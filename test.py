import subprocess
import platform


def backup_routes():
    with open("route_backup2.txt", "w") as f:
        if platform.system() == "Windows":
            result = subprocess.run("route print", capture_output=True, text=True, shell=True)
        else:
            result = subprocess.run("ip route", capture_output=True, text=True, shell=True)
        f.write(result.stdout)


backup_routes()
