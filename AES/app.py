from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)


# AES Encryption
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(
        message.encode()
    )

    # Store nonce + tag + ciphertext
    encrypted_data = cipher.nonce + tag + ciphertext

    return base64.b64encode(encrypted_data).decode()


# AES Decryption
def decrypt_message(encrypted_message, key):
    encrypted_data = base64.b64decode(encrypted_message)

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


@app.route("/", methods=["GET", "POST"])
def index():

    result = ""
    error = ""
    operation = ""

    if request.method == "POST":

        operation = request.form.get("operation")
        key_text = request.form.get("key", "")
        message = request.form.get("message", "")

        # Check key length
        if len(key_text) != 16:

            error = "Secret key must contain exactly 16 characters."

        else:

            key = key_text.encode()

            try:

                if operation == "encrypt":

                    result = encrypt_message(
                        message,
                        key
                    )

                elif operation == "decrypt":

                    result = decrypt_message(
                        message,
                        key
                    )

            except Exception:

                error = "Decryption failed. Check the key and encrypted message."

    return render_template(
        "index.html",
        result=result,
        error=error,
        operation=operation
    )


if __name__ == "__main__":
    app.run(debug=True)