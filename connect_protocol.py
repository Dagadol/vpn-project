import socket

FIXED_LEN = 4
command_list = ["connect", "dconnect", "change", "shutdown", "connect_0", "connect_1", "change_0", "change_1"]


def create_msg(data: str, cmd: str) -> bytes | None:
    # set lengths
    whole_msg_length = str(len(data))
    length_of_length = len(whole_msg_length)
    len_of_cmd = str(len(cmd))

    # check errors
    if len_of_cmd != 1 and cmd not in command_list:
        print("invalid command")
        return None
    elif length_of_length > FIXED_LEN:
        print("data length is too long (over 10^1000)")
        return None

    # set final msg
    length_of_length = str(length_of_length).zfill(FIXED_LEN)
    msg = length_of_length + len_of_cmd + cmd + whole_msg_length + data
    return msg.encode()


def get_msg(skt):
    # get lengths
    len_of_msg = int(skt.recv(FIXED_LEN).decode())
    len_of_cmd = int(skt.recv(1).decode())

    # cmd first, then msg
    cmd = skt.recv(len_of_cmd).decode()
    msg = skt.recv(len_of_msg).decode()

    return cmd, msg
