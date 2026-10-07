from flask import Flask, render_template, request
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

app = Flask(__name__)

# Generate RSA key pair when the application starts
rsa_key = RSA.generate(2048)

private_key = rsa_key
public_key = rsa_key.publickey()


# ---------------- RSA ENCRYPTION ----------------
def encrypt_message(message):
    cipher = PKCS1_OAEP.new(public_key)

    encrypted_data = cipher.encrypt(
        message.encode()
    )

    return base64.b64encode(
        encrypted_data
    ).decode()


# ---------------- RSA DECRYPTION ----------------
def decrypt_message(encrypted_message):
    encrypted_data = base64.b64decode(
        encrypted_message
    )

    cipher = PKCS1_OAEP.new(private_key)

    decrypted_data = cipher.decrypt(
        encrypted_data
    )

    return decrypted_data.decode()


# ---------------- HOME PAGE ----------------
@app.route("/", methods=["GET", "POST"])
def index():

    result = ""
    error = ""
    operation = ""

    if request.method == "POST":

        operation = request.form.get("operation")
        message = request.form.get("message", "")

        try:

            if operation == "encrypt":

                if not message:
                    error = "Please enter a message."

                else:
                    result = encrypt_message(message)

            elif operation == "decrypt":

                if not message:
                    error = "Please enter encrypted text."

                else:
                    result = decrypt_message(message)

        except Exception:

            error = (
                "Decryption failed. "
                "Please check the encrypted text."
            )

    return render_template(
        "index.html",
        result=result,
        error=error,
        operation=operation
    )


if __name__ == "__main__":
    app.run(debug=True)