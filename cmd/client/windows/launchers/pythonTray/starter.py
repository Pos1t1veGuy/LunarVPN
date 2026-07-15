import json
import queue
import threading
import traceback
from typing import *
import os, sys
import subprocess
import zipfile
import requests as rq
import time
import tkinter as tk
from tkinter import messagebox, ttk
from pathlib import Path

from tray import Tray, BASE_DIR

root_dir = Path(__file__).parent.parent
sys.path.insert(0, str(root_dir))

# relatable import brokes PyInstaller, so we need to do 2 steps back (upper the "launchers" directory) and after import lau_tools
# to compile it you must add client path (upper the "launchers" directory) to .spec "datas" list

# noinspection PyUnresolvedReferences
from lau_tools import (RELEASE, REPO_URL, CLIENT, REPO, UPDATER, VPN_SERVER_URL,
                             get_client_version, format_size_to_unit, format_size, is_admin, parse_version)

DL_UNIT = 'bytes'


def rq_get_with_retry(url: str, retries: int = 3, delay: int = 2) -> rq.Response:
    for attempt in range(retries):
        resp = rq.get(url, timeout=(10, 15))
        if resp.status_code != 200:
            time.sleep(delay)
            continue
    return resp

def get_windows_zip_version(repo_url: str) -> Tuple[str, str]:
    resp = rq_get_with_retry(f'{repo_url}/releases')
    if resp.status_code != 200:
        messagebox.showerror("Error", f"Failed to get new version")
        sys.exit(0)
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
                messagebox.showerror("Error", 'Invalid json received from github')
        else:
            messagebox.showerror("Error", 'Invalid github release url: can not find assets')
    else:
        messagebox.showerror("Error", f'Invalid github release url: can not find "{RELEASE}" release')

def download_file(url: str, dest: str = None, root: tk.Tk = None) -> Optional[str]:
    if dest is None:
        dest = os.path.basename(url)

    if root is None:
        return None

    win = tk.Toplevel(root)
    win.title("Downloading...")
    win.geometry("400x100")
    win.resizable(False, False)

    lbl = tk.Label(win, text="Connecting...")
    lbl.pack(pady=5)

    bar = ttk.Progressbar(win, mode='determinate', length=350)
    bar.pack(pady=10)

    q = queue.Queue()
    stop_event = threading.Event()
    cancel_event = threading.Event()

    def download_task():
        global DL_UNIT
        try:
            with rq.get(url, stream=True) as r:
                r.raise_for_status()
                total_size = int(r.headers.get('content-length', 0))
                formated_total = format_size(total_size, rnd=2)
                maximum = formated_total[0]
                DL_UNIT = formated_total[1]

                with open(dest, 'wb') as f:
                    downloaded = 0
                    for chunk in r.iter_content(chunk_size=8192):
                        if cancel_event.is_set():
                            q.put(('cancelled',))
                            return
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            dlded = format_size_to_unit(downloaded, DL_UNIT)
                            q.put(('progress', dlded, maximum))
        except Exception as e:
            q.put(('error', str(e)))
        else:
            q.put(('done', dest))
        finally:
            stop_event.set()

    def check_queue():
        global DL_UNIT
        try:
            while True:
                msg = q.get_nowait()
                msg_type = msg[0]

                if msg_type == 'progress':
                    _, downloaded, total = msg
                    if total:
                        bar['maximum'] = total
                        bar['value'] = downloaded
                        percent = downloaded * 100 // total
                        lbl.config(text=f"{percent}%  ({downloaded}/{total} {DL_UNIT})")
                    else:
                        bar['value'] += 1
                        lbl.config(text=f"Downloaded: {downloaded} {DL_UNIT}")

                elif msg_type == 'done':
                    lbl.config(text="Download complete! Restarting...")
                    bar['value'] = bar['maximum']
                    win.after(1500, win.destroy)
                    return

                elif msg_type == 'cancelled':
                    lbl.config(text="Cancelled by user")
                    win.after(3000, win.destroy)
                    return

                elif msg_type == 'error':
                    _, err_text = msg
                    lbl.config(text=f"Error: {err_text}")
                    win.after(3000, win.destroy)
                    return

        except queue.Empty:
            pass

        if not stop_event.is_set():
            win.after(50, check_queue)

    def on_close():
        cancel_event.set()

    win.protocol("WM_DELETE_WINDOW", on_close)
    threading.Thread(target=download_task, daemon=True).start()
    check_queue()

    root.wait_window(win)

    if cancel_event.is_set() and not os.path.exists(dest):
        return None
    return os.path.join(BASE_DIR, dest) if not os.path.isabs(dest) else dest

def check_updates(root: tk.Tk = None):
    try:
        repo_version, win_zip_url = get_windows_zip_version(REPO_URL)
    except ConnectionError:
        messagebox.showwarning("Update", "Github service is unavailable, unable to check for updates")
        return

    current_version = get_client_version(CLIENT)

    if parse_version(repo_version) > parse_version(current_version):
        agreement = messagebox.askyesno(
            "Update Available!",
            f"{REPO} client is outdated and needs to be updated.\n"
            f"Current: {current_version}  ->  New: {repo_version}\n\n"
            f"Update now?"
        )

        if agreement:
            zip_path = download_file(win_zip_url, root=root)
            if zip_path:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    if UPDATER in zf.namelist():
                        zf.extract(str(BASE_DIR / UPDATER), BASE_DIR)
                subprocess.Popen([str(BASE_DIR / UPDATER), str(zip_path)] + sys.argv[1:])
                sys.exit(0)
            else:
                messagebox.showerror("Error", "Failed to download an update.")
                sys.exit(0)

class ClientApplication:
    def __init__(self, url: str, timeout: int = 5, status_duration: int = 0.5):
        if url.endswith('/'):
            url = url[:-1]
        self.local_server_protocol, suburl = url.split('://')
        self.local_server_host, self.local_server_port = suburl.split(':')
        self.local_port = int(self.local_server_port)
        self.url = url

        self.timeout = timeout
        self.status_duration = status_duration
        self.finish = False
        self.status = {
            'version': 'N/A',
            'tunState': 'N/A',
            'connState': 'N/A',
            'conns': 0,
            'ping': 0,

            'server': 'N/A',
            'port': 0,
            'protocol': 'N/A',
            'layers': [],
        }

        self._status_loop_count = 0
        self._status_loop_started = False
        self._tunnel_locker = True

    def get(self, path: str, default: dict = {}) -> dict:
        try:
            return rq.get(f'{self.url}/{path}', timeout=self.timeout).json()
        except (rq.RequestException, json.JSONDecodeError):
            return default

    def post(self, path: str) -> int:
        try:
            return rq.post(f'{self.url}/{path}', timeout=self.timeout).status_code
        except (rq.RequestException, json.JSONDecodeError):
            return 500

    def get_status(self) -> dict:
        return self.get('status', default=self.status)
    def start_tunnel(self) -> int:
        if self._tunnel_locker:
            self._tunnel_locker = False
            res = self.post('tunnel/start')
            self._tunnel_locker = True
            return res
        return 409
    def stop_tunnel(self) -> int:
        if self._tunnel_locker:
            self._tunnel_locker = False
            res = self.post('tunnel/stop')
            self._tunnel_locker = True
            return res
        return 409
    def stop(self) -> int:
        self.finish = True
        return self.post('client/stop')

    def _get_status_loop(self):
        self._status_loop_started = True
        while not self.finish:
            self.status = self.get_status()
            time.sleep(self.status_duration)

        self._status_loop_started = False

    @property
    def version(self) -> str:
        return self.status['version']
    @property
    def tun_state(self) -> str:
        return self.status['tunState']
    @property
    def conn_state(self) -> str:
        return self.status['connState']
    @property
    def conns(self) -> int:
        return self.status['conns']
    @property
    def ping(self) -> int:
        return self.status['ping']
    @property
    def server(self) -> str:
        return self.status['server']
    @property
    def port(self) -> int:
        return self.status['port']
    @property
    def protocol(self) -> str:
        return self.status['protocol']
    @property
    def layers(self) -> List[str]:
        return self.status['layers']

    @property
    def status_loop_thread(self) -> threading.Thread:
        return threading.Thread(target=self._get_status_loop, daemon=True)
    def status_loop_thread_start(self):
        if not self._status_loop_started:
            return self.status_loop_thread.start()
        else:
            return False


if __name__ == '__main__':
    root = tk.Tk()
    try:
        root.withdraw()

        if not is_admin():
            messagebox.showerror("Error","Administrator privileges required.")
            sys.exit(0)

        if not '--update_skip' in sys.argv:
            check_updates(root=root)

        user_params = [argv for argv in sys.argv[1:] if not argv == '--update_skip']
        tray = Tray("icon.png", ClientApplication(VPN_SERVER_URL), root, user_params)

        tray.run()
        root.mainloop()

    except KeyboardInterrupt:
        pass
    except Exception as ex:
        try:
            messagebox.showerror('Error', str(ex))
            traceback.print_exc()
        except KeyboardInterrupt:
            pass
    finally:
        try:
            root.destroy()
        except:
            pass