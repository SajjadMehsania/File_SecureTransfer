from Crypto.PublicKey import RSA

key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

with open("client/client_private.pem", "wb") as f:
    f.write(private_key)

with open("server/server_public.pem", "wb") as f:
    f.write(public_key)

print("Keys generated and saved.")
