from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random
import sympy
import os


# const values
BASE = 2  # hd base
FIXED_LEN = 5
command_list = ["connect", "dconnect", "change", "shutdown", "connect_0", "connect_1", "change_0", "change_1", "error",
                "exchange", "f_conn"]


def create_msg(data: str, cmd: str, key=None) -> bytes | None:
    if key:
        data = encrypt(data.encode(), key)  # if key is available, encrypt the data
        data = data.decode('latin-1')  # data must be a string, and can't be decoded to UTF-8. this should be gibberish

    # set lengths
    whole_msg_length = str(len(data))
    length_of_length = len(whole_msg_length)
    len_of_cmd = len(cmd)

    # check errors
    if len_of_cmd != 1 and cmd not in command_list:
        print("invalid command")
        return None
    elif length_of_length > FIXED_LEN:
        print("data length is too long (over 10^10000)")
        return None

    # set final msg
    length_of_length = str(length_of_length).zfill(FIXED_LEN)
    msg = length_of_length + str(len_of_cmd) + cmd + whole_msg_length + data

    return msg.encode()


def get_msg(skt, key=None):
    """

    :param key:
    :param skt:
    :return: cmd, msg
    """
    # get lengths
    len_of_length = int(skt.recv(FIXED_LEN).decode())
    len_of_cmd = int(skt.recv(1).decode())

    # cmd first, then msg
    cmd = skt.recv(len_of_cmd).decode()
    whole_msg_length = int(skt.recv(len_of_length).decode())
    msg = skt.recv(whole_msg_length).decode()  # string of gibberish

    if key:
        msg = decrypt(msg.encode('latin-1'), key)
        msg = msg.decode()  # should be the data before the create_msg

    return cmd, msg


def get_prime():
    """
    generate secure (enough) prime for diffie-helman protocol
    :return: random prime with 2048 bits
    """
    # 2048 imo is an overkill for this project, but funny
    return sympy.nextprime(random.getrandbits(2048))


def get_key(og_base, key, mod) -> int:
    temp_base = 1
    for i in range(key):
        temp_base = temp_base * og_base % mod
    return temp_base


def dh_send(skt) -> bytes | None:
    mod = get_prime()
    my_key = random.randint(2 ** 224, 2 ** 256 - 1)  # random int between 244 to 256 bits
    public_key = get_key(BASE, my_key, mod)

    skt.send(create_msg(f"{public_key}~{mod}", "exchange"))
    cmd, data = get_msg(skt)

    if cmd != "exchange":  # error check
        print("error at dh_send:", cmd, data)
        return None

    recv_key = int(data)  # data is the key from the socket
    shared_key = str(get_key(recv_key, my_key, mod)).encode()  # encode the key

    return shared_key


def dh_get(skt) -> bytes | None:
    cmd, data = get_msg(skt)

    if cmd != "exchange":  # error check
        print("error at dh_get:", cmd, data)
        return None

    my_key = random.randint(2 ** 224, 2 ** 256 - 1)  # set random private key
    recv_key, mod = data.split("~")

    public_key = get_key(BASE, my_key, mod)
    skt.send(create_msg(str(public_key), "exchange"))

    shared_key = str(get_key(int(recv_key), my_key, int(mod))).encode()  # encode the key

    return shared_key


def encrypt(data, key):
    nonce = os.urandom(16)  # set a random nonce
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return nonce + encrypted_data


def decrypt(data, key):
    nonce = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decrypt_data = cipher.decryptor()
    return decrypt_data.update(data[16:]) + decrypt_data.finalize()
