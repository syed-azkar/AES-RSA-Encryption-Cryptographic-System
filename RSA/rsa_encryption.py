from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64


# Generate RSA key pair
key = RSA.generate(2048)

private_key = key
public_key = key.publickey()


# Display key information
print("=" * 60)
print("          RSA ENCRYPTION AND DECRYPTION")
print("=" * 60)

print("\nRSA key pair generated successfully.")

print("\nPublic Key:")
print(public_key.export_key().decode())

print("\nPrivate Key:")
print(private_key.export_key().decode())


# Get message from user
message = input("\nEnter the message to encrypt: ")


# ---------------- ENCRYPTION ----------------

cipher_encrypt = PKCS1_OAEP.new(public_key)

encrypted_message = cipher_encrypt.encrypt(
    message.encode()
)

encoded_message = base64.b64encode(
    encrypted_message
).decode()

print("\n--- ENCRYPTION ---")
print("Original Message :", message)
print("Encrypted Message:", encoded_message)


# ---------------- DECRYPTION ----------------

cipher_decrypt = PKCS1_OAEP.new(private_key)

decoded_message = base64.b64decode(
    encoded_message
)

decrypted_message = cipher_decrypt.decrypt(
    decoded_message
).decode()

print("\n--- DECRYPTION ---")
print("Decrypted Message:", decrypted_message)

print("\n" + "=" * 60)
print("RSA ENCRYPTION AND DECRYPTION COMPLETED SUCCESSFULLY")
print("=" * 60)