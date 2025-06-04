from flask import Flask, request, redirect, render_template, url_for
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from base64 import b64encode
import os
import json
import time
from werkzeug.utils import secure_filename

app = Flask(__name__, template_folder='templates')
UPLOAD_FOLDER = "uploads"
META_FILE = "meta.json"
SERVER_PUBLIC_KEY_FILE = "server_public.pem"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

with open(SERVER_PUBLIC_KEY_FILE, "rb") as f:
    public_key = RSA.import_key(f.read())
rsa_cipher = PKCS1_OAEP.new(public_key)

if os.path.exists(META_FILE):
    with open(META_FILE, "r") as f:
        metadata = json.load(f)
else:
    metadata = {}

@app.route('/')
def index():
    return render_template("upload.html")

@app.route('/upload', methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files['file']
        if not file:
            return "❌ No file uploaded", 400

        filename = secure_filename(file.filename)
        file_data = file.read()
        original_ext = os.path.splitext(filename)[1]

        aes_key = os.urandom(32)
        iv = os.urandom(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        padding_len = 16 - len(file_data) % 16
        file_data += bytes([padding_len]) * padding_len

        encrypted_data = cipher.encrypt(file_data)

        encrypted_key = rsa_cipher.encrypt(aes_key)
        encrypted_key_b64 = b64encode(encrypted_key).decode()

        enc_filename = filename + ".enc"
        with open(os.path.join(UPLOAD_FOLDER, enc_filename), "wb") as f:
            f.write(iv + encrypted_data)

        metadata[enc_filename] = {
            "upload_time": time.time(),
            "encrypted_key": encrypted_key_b64,
            "original_extension": original_ext
        }

        with open(META_FILE, "w") as f:
            json.dump(metadata, f, indent=4)

        return redirect(url_for('upload', success='true'))

    files = [f for f in os.listdir(UPLOAD_FOLDER) if f.endswith(".enc")]
    success = request.args.get("success") == "true"
    return render_template("upload.html", files=files, success=success)


if __name__ == "__main__":
    app.run(port=5000, debug=True)
