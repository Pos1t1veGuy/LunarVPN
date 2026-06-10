from typing import *
import os, sys
import ctypes
import platform
import subprocess
import zipfile
import requests as rq
import time
from pathlib import Path
from colorama import init, Fore, Style, init
init()


author = 'Pos1t1veGuy'
repo = 'LunarVPN'
client = 'client.exe'
updater = 'updater.exe'
config_file = 'profile.lunar'
RELEASE = 'commercial'
REPO_URL = f'https://api.github.com/repos/{author}/{repo}'
BASE_DIR = Path(sys.executable if getattr(sys, 'frozen', False) else __file__).parent
default_config = '''// Connection configuration

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

// Application log level (debug, info, warn, error)
logLevel="info"
// Path to logfile (by default logfile="", so it is disabled)
logfile=""

// Local server address
appHost="127.0.0.1"
appPort=8080
'''


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

def rq_get_with_retry(url: str, retries: int = 3, delay: int = 2) -> rq.Response:
    for attempt in range(retries):
        try:
            resp = rq.get(url, timeout=(10, 15))
            resp.raise_for_status()
            return resp
        except rq.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Attempt {attempt + 1}/{retries} failed: {e}{Style.RESET_ALL}")
            if attempt < retries - 1:
                time.sleep(delay)
    raise ConnectionError(f"Failed to fetch {url} after {retries} attempts")

def get_windows_zip_version(repo_url: str) -> Tuple[str, str]:
    resp = rq_get_with_retry(f'{repo_url}/releases')
    resp.raise_for_status()
    releases_json = resp.json()

    commercial_release = next((release for release in releases_json if release['tag_name'] == RELEASE), None)
    if commercial_release:
        assets = commercial_release.get('assets')
        if assets:
            try:
                win_zip = next(a for a in assets if a["name"].startswith("windows.") and a["name"].endswith('.zip'))
                zip_version = win_zip['name'].split('windows.')[1].split('.zip')[0]
                zip_url = win_zip['browser_download_url']

                return zip_version, zip_url
            except (KeyError, StopIteration):
                raise Exception('Invalid json received from github')
        else:
            raise Exception('Invalid github release url: can not find assets')
    else:
        raise Exception(f'Invalid github release url: can not find "{RELEASE}" release')

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

def download_file(url: str, dest: Optional[str] = None) -> str:
    if dest is None:
        dest = os.path.basename(url)

    with rq.get(url, stream=True) as r:
        r.raise_for_status()
        total_size = int(r.headers.get('content-length', 0))
        formated_total = format_size(total_size, rnd=2)
        max_len = len(str(formated_total[0]))
        unit = formated_total[1]
        downloaded = 0

        with open(dest, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    done = int(50 * downloaded / total_size) if total_size else 0

                    dlded = format_size_to_unit(downloaded, unit)
                    main_chars = str(dlded).split('.')[0]
                    second_chars = str(dlded).split('.')[1]

                    if len(main_chars) + 1 + len(second_chars) <= max_len:
                        formatted_dlded = str(dlded) + '0' * (max_len - len(main_chars) - 1 - len(second_chars))
                    elif len(main_chars)+1 >= max_len:
                        formatted_dlded = main_chars
                    else:
                        formatted_dlded = f'{main_chars}.{second_chars[:(max_len - len(main_chars) - 1)]}'

                    sys.stdout.write(f'\r[+] Downloading: [{Fore.GREEN}{"█" * done}{"." * (50 - done)}{Style.RESET_ALL}]'
                                     f' {formatted_dlded}/{formated_total[0]} {formated_total[1]}')
                    sys.stdout.flush()
    return dest


def check_updates():
    print(f'[+] Checking updates...')
    try:
        repo_version, win_zip_url = get_windows_zip_version(REPO_URL)
    except ConnectionError:
        print(f'{Fore.YELLOW}[w] Github service is unavailable, unable to check for updates{Style.RESET_ALL}')
        return

    current_version = get_client_version(client)

    if parse_version(repo_version) > parse_version(current_version):
        agreement = input(
            f'{Fore.GREEN}[+] {repo} client is outdated and needs to be updated. Leaving the current version may '
            f'cause compatibility issues.\n    {Fore.RED}{current_version} {Fore.GREEN}-> {Fore.YELLOW}{repo_version}\n'
            f'{Fore.GREEN}Skip updating? {Style.RESET_ALL}Y/N: ')

        if agreement.lower() in ['y', 'yes', 'н']:
            print('[-] Cancelled by user')
        else:
            print('Updating...')
            zip_path = download_file(win_zip_url)
            with zipfile.ZipFile(BASE_DIR / zip_path, 'r') as zip_ref:
                zip_ref.extract(updater, BASE_DIR)
            print(f'\n{Fore.GREEN}[+] Download finished{Style.RESET_ALL}')
            subprocess.Popen([str(BASE_DIR / updater), str(BASE_DIR / zip_path)])
            sys.exit(0)
    else:
        print(f'[+] Running {repo} client {current_version} - latest')


if __name__ == '__main__':
    try:
        if not is_admin():
            raise Exception('Administrator privileges required. Press ENTER to close...')

        if not '--update_skip' in sys.argv:
            check_updates()

        if not os.path.isfile(config_file):
            print(f'[+] Created a default config file "{config_file}"')
            print(f'[w] You need to specify "host" and "post" of LunarVPN server in config "{config_file}", default config contains empty values')
            open(config_file, 'w').write(default_config)

        print('[+] Running with profile config...')
        parameters = ' --'.join([
            line for line in open(config_file, 'r').read().split('\n')
            if not (line.startswith('#') or line.startswith('//')) and line != ""
        ])
        os.system(f'{client} --{parameters} ' + ' '.join([ argv for argv in sys.argv[1:] if not argv == '--update_skip' ]))

        input('[+] Press ENTER to exit. ')

    except KeyboardInterrupt:
        pass
    except Exception as ex:
        try:
            input(f'{Fore.RED}[e] {ex}{Style.RESET_ALL}')
        except KeyboardInterrupt:
            pass