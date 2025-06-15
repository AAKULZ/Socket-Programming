import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import sys

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt(data, public_key):
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

def decrypt(data, private_key):
    decrypted_data = b''
    try:
        decrypted_data = private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError:
        # If decryption fails, try padding the data and decrypt again
        pad_length = private_key.key_size // 8 - len(data)
        padded_data = data + b'\x00' * pad_length
        try:
            decrypted_data = private_key.decrypt(
                padded_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except ValueError:
            print("Decryption failed.")
    return decrypted_data

def receive(private_key):
    while True:
        encrypted_msg = client.recv(2048)
        print("----------------------------------------------------------------------")
        print("Server: Encrypted:", encrypted_msg)  # Print encrypted message
        try:
            decrypted_msg = decrypt(encrypted_msg, private_key).decode()
            if decrypted_msg == "Connection is Successfully Terminated!":
                print(f"SERVER: {decrypted_msg}")
                print("\n=================================================================")
                client.close()
                sys.exit()
            print("Decrypted:", decrypted_msg)  # Print decrypted message
            print("----------------------------------------------------------------------")
        except ValueError:
            print("Decryption failed.")
            break

def send(server_public_key):
    while True:
        msg = input("")
        signature = private_key.sign(
            msg.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("----------------------------------------------------------------------")
        print("Signature Created: ",signature)
        print("\n\nMessage Digitally Signed!\n")
        print("----------------------------------------------------------------------")
        # Combine message and signature
        message_with_signature = msg.encode() + signature

        encrypted_data = encrypt(message_with_signature, server_public_key)
        client.sendall(encrypted_data)

if __name__ == "__main__":
    ServerAddress = "192.168.0.5"
    Port = 8080

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ServerAddress, Port))

    private_key, public_key = generate_key_pair()

    client.send(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    server_public_pem = client.recv(4096)
    server_public_key = serialization.load_pem_public_key(server_public_pem)

    print("=================================================================\n")
    print("Private Key: ",private_key)
    print(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode())
    print("\nPublic Key: ", public_key)
    print(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())
    print("----------------------------------------------------------------------------")
    recv = threading.Thread(target=receive, args=(private_key,))
    sent = threading.Thread(target=send, args=(server_public_key,))
    recv.start()
    sent.start()

