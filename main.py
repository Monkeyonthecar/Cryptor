import os, getpass, time
from Crypto.Cipher import AES
from Crypto import Random


class cryptor_AES:
    def __init__(self, sym_key):
        self.sym_key = sym_key
        print(f"SYM KEY IS : {sym_key} ") # delete this for full hidden input

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, sym_key, sym_key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(sym_key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.sym_key)
        with open(file_name, 'wb') as fo:
            fo.write(enc)
    def decrypt(self, ciphertext, sym_key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(sym_key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo1:
            ciphertext = fo1.read()
        dec = self.decrypt(ciphertext, self.sym_key)
        with open("dec_file.mp4", 'wb') as fo2:
            fo2.write(dec)
        fo1.close()
        fo2.close()

def loading():
    spaces = 0
    x=0
    while x in range(3):
        print("\b "*spaces+".", end="", flush=True)
        spaces = spaces+1
        time.sleep(0.2)
        if (spaces>5):
            print("\b \b"*spaces, end="")
            spaces = 0
            x=x+1


while 1:
    choice = input("Choose between [ENCRYPT] en [DECRYPT]: ")
    if choice == "ENCRYPT" or choice == "encrypt" or choice == "DECRYPT" or choice == "decrypt":
        break
    print("Please choose between [ENCRYPT] en [DECRYPT]: ")

if choice == "ENCRYPT" or choice == "encrypt":
    path = input("Enter your path: ")
    sym_key = None
    while 1:
        if os.path.exists(path):
            break
        path = input("Path does not exist, enter a valid path: ")
    while not sym_key:
        sym_key = getpass.getpass("Please enter your desired symmetry key: ") # MOET 16 BYTES
        sym_key_check = getpass.getpass("Please re-enter your desired symmetry key: ")
        if sym_key_check != sym_key:
            print("Passwords do not match!")
            sym_key = None
    sym_key = str.encode(sym_key)
    sym_key = sym_key + b"\0" * (AES.block_size - len(sym_key) % AES.block_size)
    enc = cryptor_AES(sym_key)
    enc.encrypt_file(path)
    loading()
    print("FILE ENCRYPTED!")


if choice == "DECRYPT" or choice == "decrypt":
    path = input("Enter your path: ")
    while 1:
        if os.path.exists(path):
            break
        path = input("Path does not exist, enter a valid path")
    dec_key = input("Insert key: ")
    dec_key = str.encode(dec_key)
    dec_key = dec_key + b"\0" * (AES.block_size - len(dec_key) % AES.block_size)
    enc = cryptor_AES(dec_key)
    enc.decrypt_file(path)
    loading()
    print("FILE DECRYPTED!")
