from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random
import sympy
import os
import hashlib

# const values
BASE = 2  # hd base
FIXED_LEN = 4
command_list = ["connect", "dconnect", "change", "shutdown", "connect_0", "connect_1", "change_0", "change_1", "error",
                "exchange", "f_conn", "test"]


def create_msg(data: str, cmd: str, key=None) -> bytes | None:
    if key:
        data = encrypt(data.encode(), key)  # if key is available, encrypt the data; encrypt returns encoded data

    else:  # if with key data is encoded, without key it must also be encoded
        data = data.encode()

    # set lengths
    whole_msg_length = str(len(data))
    length_of_length = len(whole_msg_length)
    len_of_cmd = len(cmd)

    # check errors
    if len(str(len_of_cmd)) != 1 or cmd not in command_list:
        print("invalid command:", cmd)
        return None
    elif len(str(length_of_length)) > FIXED_LEN:
        print("data length is too long (over 10^10000)")
        return None

    # set final header config
    length_of_length = str(length_of_length).zfill(FIXED_LEN)
    header = length_of_length + str(len_of_cmd) + cmd + whole_msg_length  # headers data

    return header.encode() + data


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
    msg = skt.recv(whole_msg_length)  # might be encrypted. so encode at the end

    if key:  # if key decrypt
        msg = decrypt(msg, key)

    return cmd, msg.decode()  # decode msg here


def get_prime(bits: int = 2048) -> int:
    """
    generate secure (enough) prime for diffie-helman protocol
    :param bits: int like object, bits amount of the prime number, default is set to 2048
    :return: random prime with 2048 bits
    """
    # 2048 imo is an overkill for this project, but funny
    return sympy.nextprime(random.getrandbits(bits))


def get_key(base: int, key: int, mod: int) -> int:
    """
    exactly like `pow()`, but all values are required.

    applies non reversal math operations, used for dh key exchange protocol.
    :param base:
    :param key:
    :param mod:
    :return: pow(base, key, mod)
    """
    """
    # non optimized python version
    temp_base = 1
    for _ in range(key):
        temp_base = temp_base * base % mod
    return temp_base
    """

    # using python's built in `pow()` function is optimised in C
    return pow(base, key, mod)  # O(log key) time


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
    shared_secret = get_key(recv_key, my_key, mod)  # get the shared secret

    # convert to bytes (get the full bytes length, order by big endian)
    shared_secret_bytes = shared_secret.to_bytes(shared_secret.bit_length() + 7 // 8,  'big')  # int to bytes

    # hash the shared secret in SHA-256 for AES-256
    shared_key = hashlib.sha256(shared_secret_bytes).digest()

    return shared_key


def dh_get(skt) -> bytes | None:
    cmd, data = get_msg(skt)

    if cmd != "exchange":  # error check
        print("error at dh_get:", cmd, data)
        return None

    my_key = random.randint(2 ** 224, 2 ** 256 - 1)  # set random private key
    recv_key, mod = data.split("~")

    public_key = get_key(BASE, my_key, int(mod))
    skt.send(create_msg(str(public_key), "exchange"))

    shared_secret = get_key(int(recv_key), my_key, int(mod))
    # convert to bytes
    """
    # shared_key = str(shared_secret).encode()  # encoding the key, in string
    """
    # (get the full bytes length, order by big endian)
    shared_secret_bytes = shared_secret.to_bytes(shared_secret.bit_length() + 7 // 8,  'big')  # int to bytes

    # hash the shared secret in SHA-256 for AES-256
    shared_key = hashlib.sha256(shared_secret_bytes).digest()

    return shared_key


def encrypt(data, key):
    nonce = os.urandom(16)  # set a random nonce
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return nonce + encrypted_data


def decrypt(data, key):
    nonce = data[:16]  # get the nonce
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decrypt_data = cipher.decryptor()
    return decrypt_data.update(data[16:]) + decrypt_data.finalize()
