import customtkinter
import re  # regex
import logging
import connect_protocol


class TextboxHandler(logging.Handler):
    def __init__(self, gui):
        super().__init__()
        self.gui = gui

    def emit(self, record):
        msg = self.format(record)
        self.gui.after(0, lambda: self.gui.add_to_textbox(msg))


def block_buttons(tabs, state: str = "disabled"):
    for widget in tabs.winfo_children():
        if isinstance(widget, customtkinter.CTkButton):
            widget.configure(state=state)
        elif isinstance(widget, customtkinter.CTkTabview) or isinstance(widget, customtkinter.CTkFrame):
            block_buttons(widget, state)


def valid_params(email: str, password: str) -> str:
    if not email or not password:
        return "An entry was left unfilled"
    if "~" in "".join([email, password]):
        return "Invalid character '~' in one of the entries"
    if len(password) < 3:
        return "Password is too short"
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return "Invalid email address"
    return "OK"


class AppGUI(customtkinter.CTk):
    def __init__(self, socket=None, cmd_q=None, receiver=None, **kwargs):
        super().__init__(**kwargs)
        self.active = True  # True unless user left
        self.logger = None
        self.connected = False  # connected to a VPN server
        self.role = None  # False if not admin True if admin
        self.verified = False  # verified, server send if true.
        self.logged_in = False  # after the login screen
        self.selected_country = "Any"  # used in main
        self.geometry('700x500')
        self.minsize(500, 400)
        self.countries = []

        self.logs_textbox = None
        self.write = 0  # bool of True or False represented in 1 and 0

        self.socket = socket
        self.commands_queue = cmd_q
        self.receiver = receiver

        self.protocol("WM_DELETE_WINDOW", self._on_window_close)
        self.bind("<Configure>", self.update_dynamic_layout)  # Update layout on resize
        self.dynamic_elements = {}

    def login(self):
        def signin_btn(chosen):
            error_label.configure(text="")

            block_buttons(tabs)
            email = email_entry.get()
            password = password_entry.get()

            check = valid_params(email, password)
            if check != "OK":
                print("invalid email or password")
                error_label.configure(text=check)
                block_buttons(tabs, "normal")
                return

            data = f"{email}~{password}"
            msg = connect_protocol.create_msg(data, chosen)
            self.socket.send(msg)
            cmd, msg = self.receiver.get_thread_data(self.socket)

            if cmd != "success":
                print("reason:", msg)
                error_label.configure(text=f"{chosen} failed: {msg}")
                block_buttons(tabs, "normal")
                return

            # assign variables for states
            self.role, self.verified = msg.split("~")  # role~verified
            self.verified = self.verified == "True"
            self.logged_in = True
            self.countries = []

            if self.verified:
                # receive countries
                cmd, msg = self.receiver.get_thread_data(self.socket)
                if cmd == "countries":
                    self.countries = msg.split("~")

            self.clear_window()
            self.main()

        # Initialize properties for login state.
        self.role = None
        self.verified = None
        self.logs_textbox = None
        self.write = 0
        self.dynamic_elements["context"] = "login"
        if "logs_textbox" in self.dynamic_elements.keys():  # DELETE ME LATER
            del self.dynamic_elements["logs_textbox"]

        # Configure the grid so that the main window expands nicely.
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=0)

        # Create the TabView for the buttons.
        tabs = customtkinter.CTkTabview(self)
        tabs.grid(row=0, column=0, sticky="nsew", padx=20, pady=(20, 10))
        self.dynamic_elements["tabs"] = tabs

        # Create two tabs: one for "Log In" and one for "Sign Up".
        login_tab = tabs.add("Log In")
        signin_tab = tabs.add("Sign Up")

        # Use grid configuration for each tab (only one widget per tab here).
        for tab in (login_tab, signin_tab):
            tab.grid_columnconfigure(0, weight=1)
            tab.grid_rowconfigure(0, weight=1)

        # Create a separate frame in the root window for the shared entry fields.
        entries_frame = customtkinter.CTkFrame(self)
        entries_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(10, 20))
        # Configure the entries_frame so each column expands.
        entries_frame.grid_columnconfigure(0, weight=1)
        entries_frame.grid_columnconfigure(1, weight=1)

        # Create the shared email and password entry fields.
        email_entry = customtkinter.CTkEntry(entries_frame, placeholder_text="Enter your Email...")
        email_entry.grid(row=0, column=0, sticky="ew", padx=10, pady=10)

        password_entry = customtkinter.CTkEntry(entries_frame, placeholder_text="Enter your password...", show="*")
        password_entry.grid(row=0, column=1, sticky="ew", padx=10, pady=10)

        # Label for displaying errors
        error_label = customtkinter.CTkLabel(entries_frame, text="", text_color="red")
        error_label.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 10))

        login_submit = customtkinter.CTkButton(login_tab, text="Log In", command=lambda: signin_btn("login"))
        login_submit.place(relx=0.5, rely=0.4, anchor="center")

        signin_submit = customtkinter.CTkButton(signin_tab, text="Sign Up", command=lambda: signin_btn("signup"))
        signin_submit.place(relx=0.5, rely=0.4, anchor="center")

    def main(self):
        print("in main")

        tabs = customtkinter.CTkTabview(self)
        tabs.place(relx=0.05, rely=0.05, relwidth=0.9, relheight=0.9)  # Post-login layout
        self.dynamic_elements["tabs"] = tabs
        self.dynamic_elements["context"] = "main"

        main_tab = tabs.add("Main")
        logs_tab = tabs.add("Logs")
        user_tab = tabs.add("Settings")

        connect_btn = customtkinter.CTkButton(main_tab, text="Connect",
                                              command=lambda: self.middle_function("connect", tabs))
        disconnect_btn = customtkinter.CTkButton(main_tab, text="Disconnect",
                                                 command=lambda: self.middle_function("disconnect", tabs))
        change_btn = customtkinter.CTkButton(main_tab, text="Change",
                                             command=lambda: self.middle_function("change", tabs))

        if self.countries:
            refresh_btn = customtkinter.CTkButton(main_tab, text="Refresh",
                                                  command=lambda: self.middle_function("refresh", tabs))

            label = customtkinter.CTkLabel(main_tab, text="Choose Country")
            label.place(x=200, y=50)

            self.selected_country = self.countries[0]  # default

            def on_country_change(choice):
                self.selected_country = choice
                print(f"Selected country updated to: {self.selected_country}")

            self.country_menu = customtkinter.CTkOptionMenu(
                main_tab,
                values=self.countries,
                command=on_country_change  # gets called automatically on change
            )
            self.country_menu.set(self.selected_country)  # sets default
            self.country_menu.place(x=200, y=90)
            refresh_btn.place(x=250, y=90)

        connect_btn.place(x=40, y=50)
        disconnect_btn.place(x=40, y=120)
        change_btn.place(x=40, y=190)

        self.logs_textbox = customtkinter.CTkTextbox(logs_tab, state="disabled",
                                                     activate_scrollbars=True)
        self.logs_textbox.configure(font=("Helvetica", 14))  # Larger font
        self.logs_textbox.place(relx=0.5, rely=0.05, anchor="n", relwidth=0.9, relheight=0.75)  # Resizable
        self.dynamic_elements["logs_textbox"] = self.logs_textbox

        s_n_c = customtkinter.CTkButton(logs_tab, command=lambda: self.enable_disable(s_n_c), text="Write packets")
        delete_btn = customtkinter.CTkButton(logs_tab, command=self.clear_textbox, text="Clear")

        delete_btn.place(relx=0.75, rely=0.85, anchor="e")
        s_n_c.place(relx=0.25, rely=0.85, anchor="w")

        self.logger = logging.getLogger('vpn_logger')
        self.logger.setLevel(logging.DEBUG)

        # Remove existing handlers
        if self.logger.hasHandlers():
            self.logger.handlers.clear()

        handler = TextboxHandler(self)
        formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s',
                                      datefmt="%Y-%m-%d %H:%M:%S")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        logout_btn = customtkinter.CTkButton(user_tab, text="Log out",
                                             command=lambda: self.middle_function("logout", tabs))
        logout_btn.place(relx=0.5, rely=0.5, anchor="center")

    def middle_function(self, cmd, tabs):
        if cmd == "connect" and self.connected:
            print("Already connected")
            return
        block_buttons(tabs)
        self.commands_queue.put((cmd, self.socket))

    def enable_disable(self, btn):
        commands = ["Write packets", "Don't write packets"]
        self.write = 1 - self.write
        btn.configure(text=commands[self.write])

    def clear_textbox(self):
        if self.logs_textbox:
            self.logs_textbox.configure(state="normal")
            self.logs_textbox.delete(0.0, "end")
            self.logs_textbox.configure(state="disabled")

    def add_to_textbox(self, msg):
        if self.logs_textbox:
            if "pkt_log" in msg:
                if not self.write:
                    return
                msg = msg[0:-7]
            self.logs_textbox.configure(state="normal")
            self.logs_textbox.insert("end", f"{msg}\n")
            self.logs_textbox.configure(state="disabled")
            self.logs_textbox.see("end")

    def unblock_buttons(self):
        block_buttons(self, "normal")

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def update_dynamic_layout(self, event=None):
        """Adjust widgets based on screen size and login state."""
        ctx = self.dynamic_elements.get("context")

        # LOGIN SCREEN: ~70% height to tabs (row 0), ~30% to entries (row 1)
        if ctx == "login" and not self.logged_in:
            self.grid_rowconfigure(0, weight=7)
            self.grid_rowconfigure(1, weight=3)

        # MAIN SCREEN: use place(), but only if widgets still exist
        elif ctx == "main" and self.logged_in:
            tabs = self.dynamic_elements.get("tabs")
            if tabs and tabs.winfo_exists():
                tabs.place(relx=0.05, rely=0.05, relwidth=0.9, relheight=0.9)

            logs_tb = self.dynamic_elements.get("logs_textbox")
            if logs_tb and logs_tb.winfo_exists():
                logs_tb.place(
                    relx=0.5, rely=0.05, anchor="n",
                    relwidth=0.9, relheight=0.75
                )

    def _on_window_close(self):
        # enqueue "exit" immediately, then destroy the GUI
        self.active = False
        self.commands_queue.put(("exit", self.socket))
        while not self.commands_queue.all_tasks_done:
            connect_protocol.time.sleep(1)
        self.destroy()


if __name__ == '__main__':
    vpn_app = AppGUI()
    vpn_app.login()
    vpn_app.mainloop()
