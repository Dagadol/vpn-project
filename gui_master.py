from tkinter import *
import customtkinter
import re  # regex

import connect_protocol


def block_buttons(tabs, state: str = "disabled"):  # find a way to build this recursively; Done. is this good?
    for widget in tabs.winfo_children():
        if isinstance(widget, customtkinter.CTkButton):
            widget.configure(state=state)

        elif isinstance(widget, customtkinter.CTkTabview):
            block_buttons(widget, state)
        elif isinstance(widget, customtkinter.CTkFrame):
            block_buttons(widget, state)


def valid_params(email: str, password: str) -> bool:
    if not email or not password:  # if are not filled up
        return False

    # "~" must not be inside email and password
    if "~" in "".join([email, password]):
        # let user know somehow
        return False

    if len(password) < 3:  # too short
        # let user know
        return False

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):  # invalid email
        return False

    return True


class AppGUI(customtkinter.CTk):
    def __init__(self, socket=None, cmd_q=None, receiver=None, **kwargs):
        super().__init__(**kwargs)

        self.connected = False
        self.role = False
        self.logged_in = False
        self.geometry('650x450')

        # get params; might change it from being in kwargs
        self.socket = socket
        self.commands_queue = cmd_q
        self.receiver = receiver
        # self.login()  # start with login; maybe let vpn_client.py to decide

    def login(self):  # not finished
        def signin_btn(chosen):
            """

            :param chosen:  "signup" or "login"
            """
            block_buttons(tabs)  # block first

            # email and password checks are required, here and in the server
            # print("password:", password_entry.get())
            email = email_entry.get()
            password = password_entry.get()

            if not valid_params(email, password):  # client's side
                print("invalid email or password")
                block_buttons(tabs, "normal")  # unblock buttons
                return

            # set up msg
            data = f"{email}~{password}"
            msg = connect_protocol.create_msg(data, chosen)
            # send over to server
            self.socket.send(msg)
            cmd, msg = self.receiver.get_thread_data(self.socket)

            if cmd != "success":
                print("reason:", msg)  # don't print it in terminal, show it in the GUI
                block_buttons(tabs, "normal")  # unblock buttons
                return

            self.role = msg

            # change to main
            self.logged_in = True
            self.clear_window()  # clear window first
            self.main()

        self.role = None

        tabs = customtkinter.CTkTabview(self)
        tabs.pack(pady=10)

        login_tab = tabs.add("log in")
        signin_tab = tabs.add("sign up")

        written_password = StringVar()
        email_entry = customtkinter.CTkEntry(self, placeholder_text="Enter your Email...")
        password_entry = customtkinter.CTkEntry(self,  # textvariable=written_password,
                                                show="*",
                                                placeholder_text="Enter your password...")

        email_entry.pack(pady=15)
        password_entry.pack(pady=20)

        login_submit = customtkinter.CTkButton(login_tab, text="Log In", command=lambda: signin_btn("login"))
        login_submit.pack(pady=10)

        signin_submit = customtkinter.CTkButton(signin_tab, text="Sign In", command=lambda: signin_btn("signup"))
        signin_submit.pack(pady=10)

    def main(self):
        print("in main")

        # self.clear_window() # clear windows outside of these functions
        tabs = customtkinter.CTkTabview(self)
        tabs.pack(pady=10)

        main_tab = tabs.add("Main")
        user_tab = tabs.add("Settings")

        # main buttons/functions
        connect_btn = customtkinter.CTkButton(main_tab, text="Connnect",
                                              command=lambda: self.middle_function("connect", tabs))
        disconnect_btn = customtkinter.CTkButton(main_tab, text="Disconnnect",
                                                 command=lambda: self.middle_function("disconnect", tabs))
        change_btn = customtkinter.CTkButton(main_tab, text="Change",
                                             command=lambda: self.middle_function("change", tabs))
        logout_btn = customtkinter.CTkButton(user_tab, text="Log out",
                                             command=lambda: self.middle_function("logout", tabs))

        connect_btn.pack(pady=15, padx=25)
        disconnect_btn.pack(pady=15, padx=15)
        change_btn.pack(pady=15, padx=5)
        logout_btn.pack(pady=15, padx=35)

    def middle_function(self, cmd, tabs):
        """Pass commands from the GUI to the commands_queue"""
        if cmd == "connect":  # trying to connect in case of already connected
            if self.connected:
                print("Already connected")
                return

        # start blocking
        print("start block")
        block_buttons(tabs)
        print("end block")

        self.commands_queue.put((cmd, self.socket))

    def unblock_buttons(self):
        block_buttons(self, "normal")

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()


if __name__ == '__main__':
    vpn_app = AppGUI()
    vpn_app.login()
    vpn_app.mainloop()
