from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import os

# Functions for key generation and saving
def generate_key_pair():
    key = RSA.generate(2048)  # Generating a new key pair (2048 bits)
    public_key = key.publickey().export_key()
    private_key = key.export_key()

    with open("recipient.pem", "wb") as public_file:
        public_file.write(public_key)

    with open("private.pem", "wb") as private_file:
        private_file.write(private_key)

# Function to save encrypted or decrypted file
def save_file(file_path, data, prefix):
    file_name = f"{prefix}_{os.path.basename(file_path)}"
    with open(file_name, 'wb') as file:
        file.write(data)
    print(f"File '{file_name}' Processed Successfully!")

# Basic Encryption and Decryption
def basic_encrypt(file_path):
    try:
        with open(file_path, 'r') as file:
            data = file.read()
        encrypted_data = ''.join([chr(ord(char) + 100) for char in data])
        save_file(file_path, encrypted_data.encode(), 'encrypted_basic')
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")

def basic_decrypt(file_path):
    try:
        with open(file_path, 'rb') as file:
            data = file.read().decode()  # Read as bytes and decode to string

        decrypted_data = ''.join([chr(ord(char) - 100) for char in data])
        save_file(file_path, decrypted_data.encode(), 'decrypted_basic')
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")

# AES Encryption and Decryption
def aes_encrypt(file_path):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
        password = "16BytePassword1234"[:16]  # Truncate to 16 bytes
        cipher = AES.new(password.encode(), AES.MODE_ECB)
        pad_length = AES.block_size - len(data) % AES.block_size
        padded_data = data + bytes([pad_length] * pad_length)
        encrypted_data = cipher.encrypt(padded_data)
        save_file(file_path, encrypted_data, 'encrypted_aes')
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")

def aes_decrypt(file_path):
    try:
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
        password = "16BytePassword1234"[:16]  # Truncate to 16 bytes
        cipher = AES.new(password.encode(), AES.MODE_ECB)
        decrypted_data = cipher.decrypt(encrypted_data)

        # Remove padding
        pad_length = decrypted_data[-1]
        decrypted_data = decrypted_data[:-pad_length]

        save_file(file_path, decrypted_data, 'decrypted_aes')
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
    except Exception as e:
        print(f"Decryption Error: {e}")

# RSA Encryption and Decryption
def rsa_encrypt(file_path):
    try:
        if not os.path.isfile(file_path):
            print(f"File '{file_path}' not found.")
            return

        with open(file_path, 'rb') as file:
            data = file.read()

        recipient_key = RSA.import_key(open("recipient.pem").read())
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        encrypted_data = cipher_rsa.encrypt(data)

        save_file(file_path, encrypted_data, 'encrypted_rsa')
    except Exception as e:
        print(f"Encryption Error: {e}")

def rsa_decrypt(file_path):
    try:
        if not os.path.isfile(file_path):
            print(f"File '{file_path}' not found.")
            return

        with open(file_path, 'rb') as file:
            encrypted_data = file.read()

        private_key = RSA.import_key(open("private.pem").read())
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_data = cipher_rsa.decrypt(encrypted_data)

        save_file(file_path, decrypted_data, 'decrypted_rsa')
    except Exception as e:
        print(f"Decryption Error: {e}")

# Add the main loop to call the functions based on user choice...
# Example usage in the main loop:

generate_key_pair()

while True:
    print("\n\n===FILE ENCRYPTION SYSTEM===\n")
    print("[1] Basic Encryption\n[2] Basic Decryption\n[3] AES Encryption\n[4] AES Decryption\n[5] RSA Encryption\n[6] RSA Decryption\n[7] Exit\n")

    choice = input("Enter choice: ")

    if choice == '1':
        file_path = input("Enter the full file path to encrypt (Basic): ")
        basic_encrypt(file_path)
    elif choice == '2':
        file_path = input("Enter the full file path to decrypt (Basic): ")
        basic_decrypt(file_path)
    elif choice == '3':
        file_path = input("Enter the full file path to encrypt (AES): ")
        aes_encrypt(file_path)
    elif choice == '4':
        file_path = input("Enter the full file path to decrypt (AES): ")
        aes_decrypt(file_path)
    elif choice == '5':
        file_path = input("Enter the full file path to encrypt (RSA): ")
        rsa_encrypt(file_path)
    elif choice == '6':
        file_path = input("Enter the full file path to decrypt (RSA): ")
        rsa_decrypt(file_path)
    elif choice == '7':
        break
    else:
        print("Invalid Choice")
