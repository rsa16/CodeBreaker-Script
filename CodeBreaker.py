"""
Encoding and Decoding Gui For Multipurpouse Use.
"""

# Necessary imports
from os.path import exists, join
from os import urandom, getcwd, system
from time import sleep
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto import Random
from base64 import urlsafe_b64encode, urlsafe_b64decode, b64encode, b64decode
import hashlib
from sys import exit, argv
from argparse import ArgumentParser
from shutil import copyfile

parser = ArgumentParser(description="Encryption And Decryption CLI Tool")
parser.add_argument("Method", help="What You Want to do, i.e. encrypt, decrypt", choices=["encrypt", "decrypt"])
parser.add_argument("-t", "--Text", help="The text you want to encode.")
parser.add_argument("-f", "--filename", help="The file you want to encrypt or decrypt. Optional.")
parser.add_argument("-s", "--save_file", help="Save Output as A file")
parser.add_argument("-c", "--change_key", help="Change the Fernet key with filename")
parser.add_argument("-ca", "--change_aes_key", help="Change Fernet Key from Filename")
parser.add_argument("-sk", "--save_key", default=".", help="The location you want to save the Fernet and AES key. Left at '.', if you want to save at current location. Default is also '.'")
parser.add_argument("-skn", "--save_key_name", help="The name of the Fernet Key")
parser.add_argument("-sakn", "--save_aes_key_name", help="The name of the AES key")
parser.add_argument("-sp", "--suppress_debug_messages", action="store_true", help="This is helpful\
when utilizing this tool for a custom script, and you only want to retreive the\
output, and no debug messages, otherwise, you should probably leave this alone\
unless you know what your doing.")
parser.add_argument("-st", "--standard_file_decryption", action="store_true", help="Decrypt with special cipher and other encryptions. Helpful when -t and -s were used together whilst encrypting.")


# Necessary variables
dalpha = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
enalpha = ['1', 'c', 'd', 'e', '2', 'g', 'h', 'i', '3', 'k', 'l', 'm', 'n', 'o', '4', 'q', 'r', 's', 't', 'u', '5', 'w', 'x', 'y', 'z', '6']
specialLets = ['!', '?', ']', '[', '|', '-', '=', '*', '%', '$', '#', '@', '.', ',']

# Custom AES implementation
class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, raw):
        raw = self._pad(raw.decode())
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

# Key Logic
if not exists(join(getcwd(), 'key.txt')):
    with open("key.txt", 'wb') as f:
        f.write(b64encode(Fernet.generate_key()))
        f.close()
else:
    pass
if not exists(join(getcwd(), 'aes_key.txt')):
    with open("aes_key.txt", 'wb') as f:
        random = urandom(16)
        f.write(random)
        f.close()
else:
    pass

# Reading Keys
with open("key.txt", 'rb') as f:
    key = b64decode(f.read())
    l = Fernet(key)
    f.close()
with open("aes_key.txt", 'rb') as f:
    cipher = AESCipher(f.read())
    f.close()

# Fernet Encrypt Function
def encrypt(message: bytes) -> bytes:
    with open("key.txt", 'rb') as f:
        key = b64decode(f.read())
        f.close()
    return Fernet(key).encrypt(message)

# Fernet Decrypt Function
def decrypt(message: bytes) -> bytes:
    with open("key.txt", 'rb') as f:
        key = b64decode(f.read())
        f.close()
    return Fernet(key).decrypt(message)

# File enccrypting function.
def encodeFile(filename):
    # Read file, and if file not found, trigger error.
    try:
        with open(filename, 'rb') as f:
            read = f.read()
    except FileNotFoundError as e:
        print("File not found!")
        raise FileNotFoundError(" ")
    # Using other functions to encrypt
    encodedOutput = encrypt(read)
    encodedOutput = urlsafe_b64encode(encodedOutput)
    encodedOutput = cipher.encrypt(encodedOutput)
    # Save the new encoded output to the file, and return
    with open(filename, 'wb') as f:
        f.write(encodedOutput)
    return

# File decrypting function
def decodeFile(filename,argv=""):
    try:
        with open(filename, 'rb') as f:
            read = f.read()
    except FileNotFoundError as e:
        print("File not found")
        raise FileNotFoundError(" ")
    if (argv == ""):
        decodedOutput = cipher.decrypt(read)
        decodedOutput = urlsafe_b64decode(decodedOutput)
        decodedOutput = decrypt(decodedOutput)
    else:
        if (argv.standard_file_decryption):
            decodedOutput = decode(read)
        else:
            print(repr(read))
            decodedOutput = cipher.decrypt(read)
            print(repr(decodedOutput))
            decodedOutput = urlsafe_b64decode(decodedOutput)
            print("HI")
            print(repr(decodedOutput))
            decodedOutput = decrypt(decodedOutput)

    with open(filename, 'wb') as f:
        f.write(decodedOutput)
        f.close()
    print("File overwritten with new decoded output")
    return decodedOutput
#Encode Function
def encode(msg):
    wordlist = []
    otherwordlist = []
    found = None
    msg = msg.lower()
    theELetters = []
    for letter in msg:
        count = 0
        if letter == ' ':
            theELetters.append(letter)
            continue
        elif letter in specialLets:
            theELetters.append(letter)
            continue
        else:
            if (letter == "("):
                found = True
            if (letter == ")"):
                wordlist.append(letter)
                found = False
                theELetters.append("".join(wordlist))
                wordlist.clear()
            if (found):
                wordlist.append(letter)
        for a in dalpha:
            if letter == a:
                eletter = enalpha[count]
                theELetters.append(eletter)
            elif not letter == a:
                count +=1
    encodedOutput = ''.join(theELetters)
    encodedOutput = encodedOutput.encode()
    encodedOutput = encrypt(encodedOutput)
    encodedOutput = urlsafe_b64encode(encodedOutput)
    encodedOutput = cipher.encrypt(encodedOutput)
    return encodedOutput

#Decode Function
def decode(msg):
    wordlist = []
    otherwordlist = []
    found = None
    try:
        msg = msg.encode()
    except AttributeError as e:
        print(f"AttributeError found? {e}")
        pass

    msg = decrypt(urlsafe_b64decode(cipher.decrypt(msg))).decode()
    msg = msg.lower()
    theDLetters = []
    for letter in msg:
        count = 0
        if letter == ' ':
            theDLetters.append(letter)
            continue
        elif letter in specialLets:
            theDLetters.append(letter)
            continue
        else:
            if (letter == "("):
                found = True
                continue
            if (letter == ")"):
                found = False
                theDLetters.append("".join(wordlist))
                wordlist.clear()
            if (found):
                wordlist.append(letter)
        for a in enalpha:
            if found:
                count += 1
                continue
            if letter == a:
                dletter = dalpha[count]
                theDLetters.append(dletter)
            elif not letter == a:
                count += 1
    decodedOutput = ''.join(theDLetters)
    return decodedOutput

if (len(argv) == 1):
    # Main loop
    while True:
        print("Would you like to encode, or decode? Type * to exit. E / D")
        answer = input("> ")
        if (answer == "E") or (answer == "e"):
            print("Would you like to change the current keys? Y / N")
            a = input("> ")
            if (a == "y") or (a == "Y"):
                with open("key.txt", "wb") as f:
                    print("Name of file saved with fernet key: ")
                    an = input("> ")
                    print("Changing Fernet Key...")
                    f2 = open(an, 'rb')
                    f.write(f2.read())
                    sleep(1.5)
                    print("Changed!")
                with open ("aes_key.txt", "wb") as f:
                    print("Name of file saved with aes key: ")
                    an = input ("> ")
                    print("Changing...")
                    f.write(an.encode())
                    del cipher
                    cipher = AESCipher(an.encode())
                    sleep(1.5)
                    print("Changed!")
            if (a == "n") or (a == "N"):
                print("Okay!")
            print("Would you like to encode from command prompt, or encode a file? C / F")
            a = input("> ")
            if (a == "F") or (a == "f"):
                print("Filename?")
                try:
                    encodeFile(input("> "))
                except FileNotFoundError as e:
                    print("The passed in filename was not found!")
                    continue
                print("File encrypted")
            if (a == "C") or (a == "c"):
                encodeTest = encode(input("Encode:"))
                print(encodeTest)
            print("Where would you like to save your keys? Type '.' for current location")
            a = input("> ")
            print("What would you like to name your fernet key?")
            key_name = input("> ")
            print("What would you like to name you aes key?")
            aes_key_name = input("> ")
            with open("key.txt", "rb") as f:
                if not (a == '.'):
                    with open (join(a, key_name), "wb") as f2:
                        f2.write(f.read())
                        print(f"Fernet Key is saved as {a}/{key_name}")
                    f.close()
                else:
                    with open(key_name, "wb") as f2:
                        f2.write(f.read())
                        print(f"Fernet Key is saved as {key_name}")
                    f.close()
            with open("aes_key.txt", "rb") as f:
                if not (a == '.'):
                    with open(join(a, aes_key_name), "wb") as f2:
                        f2.write(f.read())
                        print(f"AES Key is saved as {a}/{aes_key_name}")
                    f.close()
                else:
                    with open(aes_key_name, "wb") as f2:
                        f2.write(f.read())
                        print(f"Fernet Key is saved as {aes_key_name}")
                    f.close()
            if (a == "C") or (a == "c"):
                print("Would you like to save to a file? Y / N")
                a = input("> ")
                if (a == "y") or (a == "Y"):
                    print("Name the file...")
                    b = str(input("> "))
                    with open(b, 'wb') as f:
                        print("Saving...")
                        f.write(encodeTest)
                        sleep(1.5)
                        print("Saved!")
                elif (a == "n") or (a == "N"):
                    print("Okay then!")
                    system("pause")
            system("pause")
        elif (answer == "D") or (answer == "d"):
            print("Would you like to change the current keys? Y / N")
            a = input("> ")
            if (a == "y") or (a == "Y"):
                with open("key.txt", "wb") as f:
                    print("Name of file saved with fernet key: ")
                    an = input("> ")
                    print("Changing Fernet Key...")
                    f2 = open(an, 'rb')
                    f.write(f2.read())
                    sleep(1.5)
                    f.close()
                    print("Changed!")
                with open ("aes_key.txt", "wb") as f:
                    print("Name of file saved with aes key: ")
                    an = input ("> ")
                    print("Changing AES Key...")
                    f2 = open(an, 'rb')
                    f.write(f2.read())
                    sleep(1.5)
                    f.close()
                    with open("aes_key.txt", "rb") as f:
                        del cipher
                        cipher = AESCipher(f.read())
                        f.close()
                    print("Changed!")
            if (a == "n") or (a == "N"):
                print("Okay!")
            print("Would you like to decode from command prompt, or decode a file? C / F")
            answer = input("> ")
            if (answer == "C") or (answer == "c"):
                decodeTest = decode(input("Decode:"))
                print(decodeTest)
            elif (answer == "F") or (answer == "f"):
                print("What is the name of the file you'd like to open?")
                name = input("> ")
                decodeTest = decodeFile(name)
                print("Decoding...")
                sleep(1.5)
                print("Decoded!")
                if (".txt" in name):
                    print(decodeTest.decode())
                if (".txt" in name):
                    print("Would you like to save to a file? Y / N")
                    a = input("> ")
                    if (a == "y") or (a == "Y"):
                        print("Name the file...")
                        b = str(input("> "))
                        with open(b, 'w') as f:
                            print("Saving...")
                            f.write(decodeTest)
                            sleep(1.5)
                            print("Saved!")
                    elif (a == "n") or (a == "N"):
                        print("Okay then!")
                    system("pause")
            print("Would you like to save to a file? Y / N")
            a = input("> ")
            if (a == "y") or (a == "Y"):
                print("Name the file...")
                b = str(input("> "))
                with open(b, 'w') as f:
                    print("Saving...")
                    f.write(decodeTest)
                    sleep(1.5)
                    print("Saved!")
            elif (a == "n") or (a == "N"):
                print("Okay then!")
            system("pause")
        elif (answer == "*"):
            exit()

# Argument parsing, if any
args = parser.parse_args()
if (args.Method == "encrypt"):
    if (args.change_key):
        with open("key.txt", "wb") as f:
            f2 = open(args.change_key, 'rb')
            f.write(f2.read())
        if (args.suppress_debug_messages):
            f2.close()
            f.close()
        else:
            print("Key changed")
            f2.close()
            f.close()
    if (args.change_aes_key):
        with open("aes_key.txt", "wb") as f:
            f2 = open(args.change_aes_key, 'rb')
            f.write(f2.read())
            del cipher
            cipher = AESCipher(f2.read())
            if (args.suppress_debug_messages):
                f2.close()
                f.close()
            else:
                print("AES key changed")
                f2.close()
                f.close()
    if (args.Text):
        output = encode(args.Text)
        if (args.save_file):
            with open(args.save_file, mode="wb") as f:
                f.write(output)
                f.close()
        with open("key.txt", "rb") as f:
            if not (args.save_key == '.'):
                with open(join(args.save_key, args.save_key_name), 'wb') as f2:
                    print(join(args.save_key, args.save_key_name))
                    f2.write(f.read())
                    if (args.suppress_debug_messages):
                        pass
                    else:
                        print(f"Fernet Key is saved as {args.save_key}/{args.save_key_name}")
                    f2.close()
                f.close()
            else:
                with open(args.save_key_name, "wb") as f2:
                    f2.write(f.read())
                    if (args.suppress_debug_messages):
                        pass
                    else:
                        print(f"Fernet Key is saved as {args.save_key}/{args.save_key_name}")
                f.close()
        with open("aes_key.txt", "rb") as f:
            if not (args.save_key == '.'):
                 with open(join(args.save_key, args.save_aes_key_name), 'wb') as f2:
                     f2.write(f.read())
                     if (args.suppress_debug_messages):
                         pass
                     else:
                         print(f"AES Key is saved as {args.save_key}/{args.save_aes_key_name}")
                 f.close()
            else:
                with open(args.save_aes_key_name, "wb") as f2:
                    f2.write(f.read())
                    if (args.suppress_debug_messages):
                        pass
                    else:
                        print(f"Fernet Key is saved as {args.save_key}/{args.save_aes_key_name}")
                f.close()
        print(output)
        if (args.suppress_debug_messages):
            exit()
        else:
            system("pause")
            exit()
    elif (args.filename):
        try:
            encodeFile(args.filename)
        except FileNotFoundError as e:
            if (args.suppress_debug_messages):
                exit()
            else:
                print("File was not found")
                system("pause")
                exit()
        with open("key.txt", "rb") as f:
            if not (args.save_key == '.'):
                with open(join(args.save_key, args.save_key_name), 'wb') as f2:
                    f2.write(f.read())
                    if (args.suppress_debug_messages):
                        pass
                    else:
                        print(f"Fernet Key is saved as {args.save_key}/{args.save_key_name}")
                f.close()
            else:
                with open(args.save_key_name, "wb") as f2:
                    f2.write(f.read())
                    if (args.suppress_debug_messages):
                        pass
                    else:
                        print("Fernet Key is saved as saved_key.txt")
                f.close()
        with open("aes_key.txt", "rb") as f:
            if not (args.save_key == '.'):
                with open(join(args.save_key, args.save_aes_key_name), 'wb') as f2:
                    f2.write(f.read())
                    if (args.suppress_debug_messages):
                        pass
                    else:
                        print(f"AES Key is saved as {args.save_key}/{args.save_aes_key_name}")
                f.close()
            with open(args.save_aes_key_name, "wb") as f2:
                f2.write(f.read())
                if (args.suppress_debug_messages):
                    pass
                else:
                    print("Fernet Key is saved as saved_aes_key.txt")
            f.close()
        if (args.suppress_debug_messages):
            exit()
        else:
            print("File was encrypted")
            system("pause")
            exit()
if (args.Method == "decrypt"):
    if (args.change_key):
        with open("key.txt", "wb") as f:
            f2 = open(args.change_key, 'rb')
            f.write(f2.read())
            if (args.suppress_debug_messages):
                f2.close()
                f.close()
            else:
                print("Fernet key changed")
                f2.close()
                f.close()
    if (args.change_aes_key):
        with open("aes_key.txt", "wb") as f:
            f2 = open(args.change_aes_key, 'rb')
            f.write(f2.read())
            del cipher
            cipher = AESCipher(f2.read())
            if (args.suppress_debug_messages):
                f2.close()
                f.close()
            else:
                print("AES key changed")
                f2.close()
                f.close()
    if (args.Text):
        output = decode(args.Text)
        if (args.save_file):
            with open(args.save_file, mode="wb") as f:
                f.write(output)
                f.close()
        print(output)
        if (args.suppress_debug_messages):
            exit()
        else:
            system("pause")
            exit()
    elif (args.filename):
        try:
            output = decodeFile(args.filename, args)
        except FileNotFoundError as e:
            if (args.suppress_debug_messages):
                exit()
            else:
                print("File was not found")
                system("pause")
                exit()
        if (".txt" in args.filename):
            print(output.decode())
        if (args.suppress_debug_messages):
            exit()
        else:
            print("File was decrypted")
            system("pause")
            exit()
