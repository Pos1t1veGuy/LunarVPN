from typing import *
import tkinter as tk
import pystray
import threading
import time
import sys
import subprocess
import os
from PIL import Image
from pathlib import Path
from tkinter import messagebox, ttk

from window import StatusWindow

root_dir = Path(__file__).parent.parent
sys.path.insert(0, str(root_dir))

# relatable import brokes PyInstaller, so we need to do 2 steps back (upper the "launchers" directory) and after import lau_tools
# to compile it you must add client path (upper the "launchers" directory) to .spec "datas" list

# noinspection PyUnresolvedReferences
from lau_tools import CONFIGS_FOLDER, CONFIG_FILE, DEFAULT_CONFIG, CLIENT


BASE_DIR = Path(sys.executable if getattr(sys, 'frozen', False) else __file__).parent
CONFIGS_DIR = BASE_DIR / CONFIGS_FOLDER


def get_lunar_files() -> List[Path]:
    files = list(BASE_DIR.glob('*.lunar'))
    if CONFIGS_DIR.exists():
        files += list(CONFIGS_DIR.glob('*.lunar'))
    return files


class Tray:
    def __init__(self, icon: Path, client: 'ClientApplication', root: tk.Tk, user_params: List[str]):
        self.profile_file = None
        self.reconnecting = False

        self.root = root
        self.icon_path = icon
        self.icon_image = Image.open(str(self.icon_path))
        self.client = client
        self.icon = pystray.Icon('lunarvpn', self.icon_image, 'LunarVPN', self.build_menu())
        self.menu_update_thread = threading.Thread(target=self._menu_update_loop, daemon=True)
        self.status_window = StatusWindow(self.root, self.client, self.icon_path, self)
        self.user_params = user_params

        self.finish = False
        self._last_status = self.client.status.copy()

    def run(self):
        if not os.path.isfile(CONFIG_FILE):
            open(CONFIG_FILE, 'w').write(DEFAULT_CONFIG)
        else:
            self.run_client(CONFIG_FILE)

        self.menu_update_thread.start()
        self.icon.run_detached()

    def run_client(self, config_file: str) -> int:
        self.reconnecting = True
        config_params = [
            f'--{line.replace("\"", "")}' for line in open(str(config_file), 'r').read().split('\n')
            if not (line.startswith('#') or line.startswith('//')) and line.strip() != ""
        ]
        process = subprocess.Popen([CLIENT, *config_params, *self.user_params], creationflags=subprocess.CREATE_NO_WINDOW,
                                   shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.client.status_loop_thread_start()

        http_started = False
        client_connected = False
        tunnel_created = False
        tunnel_started = False
        max_lines = 15
        successful_start = False

        for line in process.stdout:
            if 'HttpController started' in line:
                http_started = True
            if 'Client connected' in line:
                client_connected = True
            if 'Tunnel created' in line:
                tunnel_created = True
            if 'Tunnel started' in line:
                tunnel_started = True

            successful_start = http_started and client_connected and tunnel_created and tunnel_started
            if successful_start or max_lines <= 0:
                break

            max_lines -= 1

        if not successful_start:
            process.kill()
            messagebox.showerror("Failed to make connection!", f"See the logs at {Path(__file__).parent}")

        self.reconnecting = not successful_start
        self.profile_file = Path(config_file).name
        self.update_menu()
        return int(successful_start)

    def close(self):
        self.finish = True
        self.icon.stop()
        self.client.stop()
        try:
            self.root.after(0, self.root.quit)
        except RuntimeError:
            pass
        sys.exit()

    def build_menu(self):
        menu_items = [pystray.MenuItem('Open Window', self.show_window, default=True)]

        if self.client.tun_state == 'opened':
            menu_items.append(
                pystray.MenuItem('Disconnect', self.toggle_tunnel_connection)
            )
        elif self.client.tun_state == 'closed':
            menu_items.append(
                pystray.MenuItem('Connect', self.toggle_tunnel_connection)
            )
        elif self.client.tun_state == 'N/A':
            menu_items.append(
                pystray.MenuItem('Waiting...', None, enabled=False)
            )
        else:
            state = 'Connecting' if self.client.tun_state == 'opening' else 'Disconnecting'
            menu_items.append(pystray.MenuItem(state, None, enabled=False))

        menu_items.append(pystray.Menu.SEPARATOR)

        config_menu_items = [pystray.MenuItem(
            (f'✓ {file.name}' if file.name == self.profile_file else file.name), self.select_config, enabled=not self.reconnecting
        ) for file in get_lunar_files()]
        if config_menu_items:
            config_menu = pystray.Menu(*config_menu_items)
            menu_items.append(pystray.MenuItem('Configs', config_menu))
        else:
            menu_items.append(pystray.MenuItem('Configs (empty)', None, enabled=False))

        menu_items.append(pystray.Menu.SEPARATOR)
        menu_items.append(pystray.MenuItem('Exit', self.on_exit))

        return pystray.Menu(*menu_items)

    def update_menu(self):
        self.icon.menu = self.build_menu()
        if hasattr(self.icon, 'update_menu'):
            self.icon.update_menu()

    def _menu_update_loop(self):
        while not self.finish:
            if self._last_status != self.client.status:
                self._last_status = self.client.status.copy()
                self.update_menu()
            time.sleep(0.1)

    def toggle_tunnel_connection(self, icon, item):
        if self.client.tun_state == 'closed':
            threading.Thread(target=self.client.start_tunnel, daemon=True).start()
            self.client.status['tunState'] = 'opening'
        elif self.client.tun_state == 'opened':
            threading.Thread(target=self.client.stop_tunnel, daemon=True).start()
            self.client.status['tunState'] = 'closing'
        else: # opening/closing
            return

    def show_window(self, icon, item=None):
        if not self.finish:
            self.root.after(0, self._show_window)

    def _show_window(self):
        if self.status_window.state() == "withdrawn":
            self.status_window.deiconify()
            self.status_window.lift()
            self.status_window.focus_force()
        else:
            self.status_window.withdraw()

    def select_config(self, icon, item):
        self.reconnecting = True
        self.update_menu()
        filepath = ''
        if os.path.isfile(BASE_DIR / item.text):
            filepath = BASE_DIR / item.text
        elif os.path.isfile(CONFIGS_DIR / item.text):
            filepath = CONFIGS_DIR / item.text
        else:
            return

        def restart_client():
            self.client.post('client/stop')
            time.sleep(1 + self.client.status_duration)
            self.run_client(filepath)
            self.update_menu()

        threading.Thread(target=restart_client, daemon=True).start()

    def on_exit(self, icon, item):
        self.close()