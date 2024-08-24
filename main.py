import os
import base64
import getpass
from termcolor import colored
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

base64_enable = True


def list_files():
    files = [f for f in os.listdir() if os.path.isfile(f)]
    for i, file in enumerate(files, 1):
        decript_name = file

        if base64_enable:
            try:
                dec_name = decript_name
                count = 0
                while True:
                    try:
                        dec_name = dec_name.replace("_de", "")
                        dec_name = base64.b64decode(dec_name.encode()).decode()
                        count += 1
                    except:
                        break

                if count:
                    decript_name = decript_name + colored(" (Base64 Decripted) ",
                                                          "blue") + f"=> {colored(dec_name, 'green')}"
                else:
                    decript_name = colored(file, "yellow")

            except:
                pass
        else:
            decript_name = colored(file, "yellow")

        print(f"{i}: {decript_name}")
    return files


def get_unique_filename(filename, suffix):
    if suffix == "de":
        if base64_enable:
            try:
                filename = base64.b64decode(filename.encode()).decode()
            except:
                pass

        filename = filename.replace("_en", "")

    base, ext = os.path.splitext(filename)
    unique_filename = f"{base}_{suffix}{ext}"

    if base64_enable:
        if suffix == "en":
            unique_filename = base64.b64encode(unique_filename.encode()).decode()

    counter = 1
    while os.path.exists(unique_filename):
        unique_filename = f"{base}_{suffix}_{counter}{ext}"

        if base64_enable:
            if suffix == "en":
                unique_filename = base64.b64encode(unique_filename.encode()).decode()

        counter += 1
    return unique_filename


def encrypt_file(password, file_path, output_path):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)

    with open(file_path, 'rb') as file:
        file_data = file.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_path, 'wb') as file:
        file.write(salt + iv + encrypted_data)


def decrypt_file(password, file_path, output_path):
    with open(file_path, 'rb') as file:
        salt = file.read(16)
        iv = file.read(16)
        encrypted_data = file.read()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    try:
        file_data = unpadder.update(padded_data) + unpadder.finalize()
    except:
        print(colored("Faild, Wrong Password..!", "red"))
        exit()

    with open(output_path, 'wb') as file:
        file.write(file_data)


def main():
    print("Select a file to process:")
    files = list_files()
    file_index = int(input("Enter the number of the file: ")) - 1
    input_path = files[file_index]

    choice = input("Enter 'e' to encrypt or 'd' to decrypt: ").lower()
    while not choice in ["e", "d"]:
        print(colored("\n\nInvalid choice. Please enter 'e' to encrypt or 'd' to decrypt.", "red"))
        choice = input("Enter 'e' to encrypt or 'd' to decrypt: ").lower()

    password = getpass.getpass("Enter password: ")

    if choice == "e":
        retry_password = getpass.getpass("Re-Enter password: ")

        while password != retry_password:
            print(colored("Paswords Doesn't Mach...! Try Again...", "red"))
            password = getpass.getpass("Enter password: ")
            retry_password = getpass.getpass("Re-Enter password: ")


    output_path = input("Enter the output file path (leave empty for automatic naming): ").strip()
    if not output_path:
        suffix = "en" if choice == 'e' else "de"
        output_path = get_unique_filename(input_path, suffix)
    else:
        output_path = input_path
        if base64_enable:
            output_path = base64.b64encode(input_path.encode()).decode()

    print("\n\n" + "-" * 20)
    print(colored("Processing...", "yellow"))

    if choice == 'e':
        encrypt_file(password, input_path, output_path)
        print(colored(f"\n\nFile encrypted successfully as {output_path}.", "green"))
    elif choice == 'd':
        decrypt_file(password, input_path, output_path)
        print(colored(f"\n\nFile decrypted successfully as {output_path}.", "green"))


if __name__ == "__main__":
    main()
