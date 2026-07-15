from pathlib import Path
import tkinter as tk
import threading


BG = "#1E1E1E"
CARD = "#2B2B2B"

TEXT = "#FFFFFF"
SECOND = "#AAAAAA"

GREEN = "#00C853"
RED = "#F44336"
ORANGE = "#FFB300"

BUTTON = "#5865F2"
DISABLED_BUTTON = "#555555"
ACTION_BUTTON = "#7289DA"

FONT_MAIN1 = ("Segoe UI", 18, "bold")
FONT_MAIN2 = ("Segoe UI", 14, "bold")
FONT_BASE = ("Segoe UI", 10)
FONT_BASE_BOLD = ("Segoe UI", 10, "bold")


class StatusWindow(tk.Toplevel):
    def __init__(self, master: tk.Tk, client: 'ClientApplication', icon_path: Path, tray: 'Tray'):
        super().__init__(master)

        self._tun_restating = False
        self._last_tun_state = None
        self.x, self.y = 0, 0

        self.tray = tray
        self.configure(bg="#AAAAAA")
        self.width = 360
        self.height = 600
        self.screenwidth = master.winfo_screenwidth()
        self.screenheight = master.winfo_screenheight()
        self.overrideredirect(True)

        x = self.screenwidth - self.width - 40
        y = self.screenheight - self.height - 90
        self.geometry(f"{self.width}x{self.height}+{x}+{y}")
        self.title("LunarVPN")
        self.resizable(False, False)
        self.iconphoto(True, tk.PhotoImage(file=str(icon_path)))
        self.protocol("WM_DELETE_WINDOW", self.withdraw)
        self.client = client

        self.border = tk.Frame(self,bg="#AAAAAA")
        self.border.configure(bg=BG)
        self.border.pack(fill="both",expand=True,padx=5,pady=5)
        self.bind("<Button-1>", self.start_move)
        self.bind("<B1-Motion>",self.move_window)
        self.bind("<FocusOut>", lambda e: self.withdraw() if self.focus_get() is None else None)

        self.border.columnconfigure(0, weight=1)
        self.border.grid_rowconfigure(0, minsize=15)
        title = tk.Label(self.border, text="LunarVPN", font=FONT_MAIN1, fg=TEXT, bg=BG)
        title.grid(row=0, column=0, pady=(15, 5))

        self.circle = tk.Canvas(self.border, width=70, height=70, bg=BG, highlightthickness=0)
        self.indicator = self.circle.create_oval(10, 10, 60, 60, fill="red", outline="")
        self.circle.grid(row=1, column=0)
        self.status_label = tk.Label(self.border, text="Disconnected", font=FONT_MAIN2, bg=BG, fg=TEXT)
        self.status_label.grid(row=2, column=0, pady=(0, 15))

        separator = tk.Frame(self.border, bg="#404040", height=1)
        separator.grid(row=4, column=0, sticky="ew", padx=20, pady=(10, 15))

        self.version = self.create_card(3, "Version")
        self.ping = self.create_card(4, "Ping")
        self.connections = self.create_card(5, "Connections")
        self.server = self.create_card(6, "Server")
        self.protocol = self.create_card(7, "Protocol")
        self.config = self.create_card(8, "Config")

        self.action_btn = tk.Label(
            self.border,
            text="CONNECT",
            font=FONT_BASE_BOLD,
            bg=BUTTON,
            fg="white",
            relief="flat",
            height=2,
        )

        self.action_btn.grid(row=9, column=0, sticky="ew", padx=20, pady=20)
        self.action_btn.bind("<Button-1>", lambda e: self.toggle_connection())
        self.action_btn.bind("<Enter>", self.on_button_hover)
        self.action_btn.bind("<Leave>", self.on_button_leave)

        self.withdraw()
        self.refresh_ui()
        self.update_loop()

    def create_card(self, row, title):
        frame = tk.Frame(self.border, bg=CARD, bd=1, relief="solid", highlightthickness=0)
        frame.grid(row=row, column=0, sticky="ew", padx=20, pady=4)
        frame.columnconfigure(1, weight=1)

        frame.columnconfigure(1, weight=1)

        title_lbl = tk.Label(frame, text=title, bg=CARD, fg=SECOND, font=FONT_BASE)

        title_lbl.grid(row=0, column=0, padx=12, pady=10, sticky="w")

        value = tk.Label(frame, text="-", fg=TEXT, bg=CARD, font=FONT_BASE_BOLD)
        value.grid(row=0, column=1, padx=10, sticky="e")
        return value

    def on_button_hover(self, event):
        if self.action_btn["state"] == "normal":
            self.action_btn.config(
                bg=ACTION_BUTTON
            )

    def on_button_leave(self, event):
        if self.action_btn["state"] == "normal":
            self.action_btn.config(
                bg=BUTTON
            )

    def start_move(self, event):
        self.x = event.x
        self.y = event.y

    def move_window(self, event):
        dx = event.x - self.x
        dy = event.y - self.y
        self.geometry(f"+{self.winfo_x() + dx}+{self.winfo_y() + dy}")

    def get_ui_state(self):
        if self.tray.reconnecting:
            return "RECONNECTING"

        if self._tun_restating:
            if self._last_tun_state == "opened":
                return "DISCONNECTING"
            return "CONNECTING"

        if self.client.tun_state == "opened":
            if self.client.conn_state == "connected":
                return "CONNECTED"

            if self.client.conn_state == "connecting":
                return "CONNECTING"

            if self.client.conn_state == "disconnecting":
                return "DISCONNECTING"

        return "DISCONNECTED"

    def refresh_ui(self):
        tun_state = self.client.tun_state
        connection_state = self.client.conn_state

        self.version.config(text=self.client.version)
        self.ping.config(text=f"{self.client.ping} ms" if not self.tray.reconnecting else 'N/A')
        self.connections.config(text=str(self.client.conns) if not self.tray.reconnecting else 'N/A')
        self.server.config(text=f"{self.client.server}:{self.client.port}" if not self.tray.reconnecting else 'N/A')
        self.protocol.config(text=self.client.protocol.upper() if not self.tray.reconnecting else 'N/A')
        self.config.config(text=self.tray.profile_file if not self.tray.reconnecting else 'N/A')

        # button click doing POST request, after that client doing a command
        # It is time after successful request and after client reaction, that changes his status to opposite (o->c and o<-c)
        if tun_state in ['opened', 'closed'] and tun_state != self._last_tun_state and self._tun_restating:
            self._tun_restating = False
            self._last_tun_state = tun_state


        if tun_state == "opened" and not self._tun_restating and connection_state == "connected" and not self.tray.reconnecting:
            self.circle.itemconfig(self.indicator, fill=GREEN)
            self.status_label.config(text="Connected")
            self.action_btn.config(text="DISCONNECT", state="normal", bg=BUTTON)

        elif tun_state == "closed" and not self._tun_restating:
            self.circle.itemconfig(self.indicator, fill=RED)
            self.status_label.config(text="Disconnected")
            self.action_btn.config(text="CONNECT", state="normal", bg=BUTTON)

        else:
            self.circle.itemconfig(self.indicator, fill=ORANGE)
            self.status_label.config(text=self.get_ui_state().capitalize())
            self.action_btn.config(text="LOADING...", bg=DISABLED_BUTTON)

    def update_loop(self):
        self.refresh_ui()
        self.after(500, self.update_loop)

    def _do_connect(self):
        self.client.start_tunnel()

    def toggle_connection(self):
        if self._tun_restating:
            return
        if self.client.tun_state == "closed":
            self.client.status['tunState'] = "opening"
            self.refresh_ui()
            self._tun_restating = True
            self._last_tun_state = "closed"
            threading.Thread(
                target=self.client.start_tunnel,
                daemon=True
            ).start()
        elif self.client.tun_state == "opened":
            self.client.status['tunState'] = "closing"
            self.refresh_ui()
            self._tun_restating = True
            self._last_tun_state = "opened"
            threading.Thread(
                target=self.client.stop_tunnel,
                daemon=True
            ).start()

    def _do_disconnect(self):
        self.client.stop_tunnel()