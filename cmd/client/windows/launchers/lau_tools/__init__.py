from typing import *
import sys, os
import ctypes
import subprocess
import platform

AUTHOR = 'Pos1t1veGuy'
REPO = 'LunarVPN'
CLIENT = 'client.exe'
UPDATER = 'updater.exe'
CONFIG_FILE = 'profile.lunar'
RELEASE = 'commercial'
REPO_URL = f'https://api.github.com/repos/{AUTHOR}/{REPO}'
VPN_SERVER_URL = 'http://localhost:8080'
CONFIGS_FOLDER = 'configs'

DEFAULT_CONFIG = '''// Connection configuration

host=""
port=0
login="admin"
password="admin"

blacklist="blacklist.txt"
whitelist="whitelist.txt"

// Type of connection to server (udp, udpPool, tcp, tcpPool). "Pool" is 2-8 connections simultaneously
connType="udpPool"

// Type of HANDSHAKE encryption. 0: Debug; 1: Xor (use -listLayers to view all)
defaultLayer=1
// Type of CONNECTION encryption. Comma-separated layer indexes, e.g. 1,4,5 (use -listLayers to view all)
layers=1
// Key to encrypt network traffic. Random user string with only "[a-z][0-9]_-"
cipherKey="LunarVPN"

// Application log level (debug, info, warn, error)
logLevel="info"
// Path to logfile (by default logfile="", so it is disabled)
logfile=""

// Local server address
appHost="127.0.0.1"
appPort=8080
'''


def run_as_admin(exe_path: str, params: List[str]):
    # if sys.platform != 'win32':
    #     raise OSError("Windows only")

    # UAC (launch starter as admin)
    ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        exe_path,
        ' '.join(params),
        None,
        1
    )
    sys.exit(0)

def is_admin() -> bool:
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        return os.geteuid() == 0

def parse_version(v: str) -> tuple[int, ...]:
    v = v.lstrip('v').split('-')[0]
    parts = [int(p) for p in v.split('.') if p.isdigit()]
    return tuple(parts)

def get_client_version(client_path: str) -> str:
    return subprocess.run(
        client_path.split() + ["--version"],
        capture_output=True,
        text=True
    ).stdout.strip()

def format_size(size_bytes: int, rnd: int = 0) -> Tuple[float, str]:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return round(float(size_bytes), rnd), unit
        size_bytes /= 1024
    return round(float(size_bytes), rnd), 'TB'

def format_size_to_unit(size_bytes: int, unit: str) -> float:
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    if unit in units:
        return size_bytes / 1024**units.index(unit)

    raise ValueError(f'"unit" kwarg must be string, one from {units}')