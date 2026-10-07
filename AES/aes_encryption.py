from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64


# ---------------- AES ENCRYPTION ----------------
def encrypt_message(message, key):

    cipher = AES.new(key, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(
        message.encode()
    )

    # Store nonce + tag + ciphertext
    encrypted_data = cipher.nonce + tag + ciphertext

    return base64.b64encode(encrypted_data).decode()


# ---------------- AES DECRYPTION ----------------
def decrypt_message(encrypted_message, key):

    encrypted_data = base64.b64decode(
        encrypted_message
    )

    # Extract nonce, tag and ciphertext
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]

    cipher = AES.new(
        key,
        AES.MODE_EAX,
        nonce=nonce
    )

    decrypted_message = cipher.decrypt_and_verify(
        ciphertext,
        tag
    )

    return decrypted_message.decode()


# ---------------- MAIN PROGRAM ----------------
while True:

    print("\n")
    print("=" * 50)
    print("        AES CRYPTOGRAPHIC SYSTEM")
    print("=" * 50)
    print("1. Encrypt Message")
    print("2. Decrypt Message")
    print("3. Exit")
    print("=" * 50)

    choice = input("Enter your choice: ")

    # -------- ENCRYPTION --------
    if choice == "1":

        print("\n--- AES ENCRYPTION ---")

        key_text = input(
            "Enter a 16-character secret key: "
        )

        if len(key_text) != 16:
            print(
                "Error: Key must contain exactly 16 characters."
            )
            continue

        message = input(
            "Enter the message to encrypt: "
        )

        key = key_text.encode()

        encrypted_message = encrypt_message(
            message,
            key
        )

        print("\nEncryption Successful!")
        print("Original Message :", message)
        print("Secret Key       :", key_text)
        print("Encrypted Message:", encrypted_message)

    # -------- DECRYPTION --------
    elif choice == "2":

        print("\n--- AES DECRYPTION ---")

        key_text = input(
            "Enter the 16-character secret key: "
        )

        if len(key_text) != 16:
            print(
                "Error: Key must contain exactly 16 characters."
            )
            continue

        encrypted_message = input(
            "Enter the encrypted message: "
        )

        try:

            key = key_text.encode()

            decrypted_message = decrypt_message(
                encrypted_message,
                key
            )

            print("\nDecryption Successful!")
            print("Decrypted Message:", decrypted_message)

        except Exception:

            print(
                "Error: Decryption failed."
                " Check the key and encrypted message."
            )

    # -------- EXIT --------
    elif choice == "3":

        print("\nThank you for using AES Cryptographic System!")
        break

    else:

        print("\nInvalid choice. Please select 1, 2 or 3.")