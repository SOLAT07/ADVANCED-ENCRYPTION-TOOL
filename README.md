# ADVANCED-ENCRYPTION-TOOL

# COMPANY: CODTECH IT SOLUTIONS

# NAME: RAJ SOLAT

# INTERN ID: CT08LKC

# DOMAIN:  Cyber Security & Ethical Hacking

# DURATION: 4 WEEEKS

# MENTOR: NEELA SANTOSH

# DESCRIPTION :-

1. Purpose: Encrypt and decrypt messages using AES-256 encryption.
2. Encryption:
Takes a message and a password.
Generates a random salt.
Uses the password and salt to create a sedure key.
• Encrypts the message and outputs the cipher text, salt, nonce, and tag.
3. Decryption:
Takes the cipher text, salt, nonce, tag, and password.
Recreates the key using the password and salt.
Decrypts the cipher text and verifies its integrity,
4. How It Works:
You choose to encrypt or decrypt.
For encryption, you input a message and password, and it gives encrypted data.
For decryption, you input encrypted data and the same password to get the original message.

Step-by-Step Implementation

Let’s break down the Python implementation into key steps.


1. Setting Up the Environment
Before diving into the code, ensure you have the necessary libraries installed. Use the following commands to install the required dependencies:

pip install pycryptodome
pip install pycryptodomex
Copy

2. Encryption Function
The encrypt function takes a plain text and a password, generates a random salt, and derives a secure key using the password and salt with the scrypt algorithm.
It then encrypts the data using AES-256 in GCM mode. Here’s the key part of the encryption process:

def encrypt(plain_text, password):
    if not password:
        raise ValueError("Password cannot be empty.")
    salt = get_random_bytes(AES.block_size)
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32
    )
    cipher_config = AES.new(private_key, AES.MODE_GCM)
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, "utf-8"))
    return {
        "cipher_text": b64encode(cipher_text).decode("utf-8"),
        "salt": b64encode(salt).decode("utf-8"),
        "nonce": b64encode(cipher_config.nonce).decode("utf-8"),
        "tag": b64encode(tag).decode("utf-8"),
    }

3. Decryption Function

The decrypt function reverses the encryption process. It uses the password and saved salt to recreate the encryption key,
decrypts the cipher text, and verifies its integrity using the tag.


def decrypt(enc_dict, password):
    if not password:
        raise ValueError("Password cannot be empty.")
    salt = b64decode(enc_dict["salt"])
    cipher_text = b64decode(enc_dict["cipher_text"])
    nonce = b64decode(enc_dict["nonce"])
    tag = b64decode(enc_dict["tag"])
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32
    )
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)
    return decrypted.decode("utf-8")
Copy


4. Save and Load Encrypted Data

To make the program more user-friendly, encrypted data can be saved to a JSON file and loaded later for decryption. 
Here are the helper functions:


Save Data:

def save_to_file(data, filename="encrypted_data.json"):
    with open(filename, "w") as file:
        json.dump(data, file)
    print(f"\nEncrypted data saved to {filename}")

Load Data:

def load_from_file(filename="encrypted_data.json"):
    if not os.path.exists(filename):
        raise FileNotFoundError(f"No file found at {filename}")
    with open(filename, "r") as file:
        return json.load(file)

5. Main Program

The program allows the user to:


Encrypt a message and save it to a file.
Decrypt a message using the saved file and password.

def main():
    print("\t\tAES 256 Encryption and Decryption Algorithm")
    x = input(""" 
               Enter
               1 to encrypt 
               2 to decrypt
               : 
              """)
    if x == "1":
        password = input("Enter the Password: ")
        secret_mssg = input("\nEnter the Secret Message: ")
        encrypted = encrypt(secret_mssg, password)
        print("\n\nEncrypted Data:")
        for k, v in encrypted.items():
            print(f"{k}: {v}")
        save_to_file(encrypted)

    elif x == "2":
        filename = input("Enter the filename to load encrypted data (default: encrypted_data.json): ") or "encrypted_data.json"
        encrypted = load_from_file(filename)
        password = input("Enter the password: ")
        decrypted = decrypt(encrypted, password)
        print("\n\nDecrypted Message:")
        print(decrypted)

Running the Code

1.Save the code to a file, e.g., AES256.py.
2.Run the script in the terminal:bashCopy codepython3 AES256.py
3.Follow the prompts to encrypt or decrypt a message.
