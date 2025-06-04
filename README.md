🔐 File Secure Transfer – Python Server-Client Cybersecurity Demo
This project demonstrates cybersecurity concepts using a simple Python-based server-client architecture.

🗂️ Server Side:
Users can upload files which are then AES encrypted and stored in the uploads/ folder.
The AES key is securely encrypted with RSA and stored in metadata.

👨‍💻 Client Side:
The client can view a list of encrypted files and decrypt them within 10 minutes of upload.
The system enforces time-based access control using the upload timestamp.

🔐 Key Features
AES + RSA hybrid encryption

Time-restricted decryption (10 minutes)

Secure key exchange

Client-server architecture with Flask

User-friendly upload and decrypt interface
