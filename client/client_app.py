from flask import Flask, render_template, send_file, request
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import os
import json
import time
from base64 import b64decode

app = Flask(__name__, template_folder='templates')

SERVER_META_FILE = os.path.join("..", "server", "meta.json")
SERVER_UPLOADS_FOLDER = os.path.join("..", "server", "uploads")
CLIENT_PRIVATE_KEY_FILE = "client_private.pem"
DECRYPTED_FOLDER = "decrypted"
DECRYPT_TIME_LIMIT = 600  

with open(CLIENT_PRIVATE_KEY_FILE, "rb") as f:
    private_key = RSA.import_key(f.read())
rsa_cipher = PKCS1_OAEP.new(private_key)

os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

def load_metadata():
    if not os.path.exists(SERVER_META_FILE):
        return {}
    with open(SERVER_META_FILE, "r") as f:
        return json.load(f)

@app.route('/')
def index():
    metadata = load_metadata()
    now = time.time()
    file_list = []

    for filename, info in metadata.items():
        upload_time = info.get('upload_time', 0)
        time_remaining = int(DECRYPT_TIME_LIMIT - (now - upload_time))
        file_list.append({
            "name": filename,
            "time_remaining": max(time_remaining, 0)
        })

    return render_template("client_files.html", file_list=file_list)

@app.route('/decrypt/<filename>', methods=["POST"])
def decrypt_file(filename):
    metadata = load_metadata()
    file_info = metadata.get(filename)

    if not file_info:
        return "File metadata not found", 404

    elapsed_time = time.time() - file_info.get('upload_time', 0)
    if elapsed_time > DECRYPT_TIME_LIMIT:
        return "❌ Decryption window expired (10 minutes passed)", 403

    encrypted_key = b64decode(file_info['encrypted_key'])
    original_ext = file_info.get('original_extension', '')

    symmetric_key = rsa_cipher.decrypt(encrypted_key)

    input_file_path = os.path.join(SERVER_UPLOADS_FOLDER, filename)
    with open(input_file_path, "rb") as f:
        iv = f.read(16)
        cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
        encrypted_data = f.read()
        decrypted_data = cipher.decrypt(encrypted_data)

    pad_len = decrypted_data[-1]
    decrypted_data = decrypted_data[:-pad_len]

    output_filename = os.path.splitext(filename)[0] + original_ext
    output_path = os.path.join(DECRYPTED_FOLDER, output_filename)

    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    return send_file(output_path, as_attachment=True)

if __name__ == '__main__':
    app.run(port=5001, debug=True)
