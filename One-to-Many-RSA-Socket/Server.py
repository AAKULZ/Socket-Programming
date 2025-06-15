import socket
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import random

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
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

class ClientThread(threading.Thread):
    count = 1
    instanceArr = []
    public_keys = {}

    def __init__(self, clientAddress, clientsocket,public_key,private_key):
        threading.Thread.__init__(self)
        self.__class__.instanceArr.append(self)
        self.csocket = clientsocket
        self.clientAddress = clientAddress
        self.passkey = str(random.randint(100, 999))
        self.csocket.send(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
        print("----------------------------------------------------------------------")
        print(f"New Connection Added [Address:{clientAddress[0]} Port:{clientAddress[1]}]")
        print(f"Total connections: {ClientThread.count}")
        print("----------------------------------------------------------------------")
        if ClientThread.count == 5:
            print("Queue already Reached to Limit!!")
            print("No More Connections Allowed!")
            print("----------------------------------------------------------------------")
        ClientThread.count = ClientThread.count + 1

    def run(self):
        client_public_pem = self.csocket.recv(2048)
        self.public_key = serialization.load_pem_public_key(client_public_pem)
        self.__class__.public_keys[self.clientAddress] = self.public_key
        self.csocket.send(encrypt(bytes(f"Welcome to Server..\nTo Quit Enter:{self.passkey}", "utf-8"), self.public_key))
        msg = "a"
        while msg:
            encrypted_msg = self.csocket.recv(4096)
            try:
                decrypted_msg = decrypt(encrypted_msg, private_key)
                received_message = decrypted_msg[:-256]
                received_signature = decrypted_msg[-256:]
            
                # Verify signature
                self.public_key.verify(
                    received_signature,
                    received_message,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                print("----------------------------------------------------------------------")
                print("Verified Signature:", received_signature.hex())
                print("\n\nUser Authenticated Successfully!!\n")
                decrypted_msg = received_message.decode()
                if decrypted_msg == self.passkey:
                    self.csocket.send(encrypt(bytes(f"Connection is Successfully Terminated!", "utf-8"), self.public_key))
                    break
                print("----------------------------------------------------------------------")
                print(f"{self.clientAddress[0]}: Encrypted: {encrypted_msg}, \nDecrypted: {decrypted_msg}")
                print("----------------------------------------------------------------------")
                for cli in ClientThread.instanceArr:
                    if cli.clientAddress != self.clientAddress:
                        cli.csocket.send(encrypt(bytes((self.clientAddress[0] + ": " + decrypted_msg), "UTF-8"), cli.__class__.public_keys[cli.clientAddress]))
            except ValueError:
                print("Decryption failed.")
                break
        print(f"Old Connection Closed [Address:{self.clientAddress[0]} Port:{self.clientAddress[1]}]")

def send():
    while True:
        msg = input("")
        for cli in ClientThread.instanceArr:
            encrypted_msg = encrypt(bytes(msg, "UTF-8"), cli.public_key)
            cli.csocket.send(encrypted_msg)

flag = 1
LocalHost = "192.168.0.5"
Port = 8080
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((LocalHost, Port))
private_key, public_key = generate_key_pair()
print("============================================================================")

print(f"Server Has been Initialized on Address:{LocalHost} Port:{Port}\n")
print("----------------------------------------------------------------------------")
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
print("Possible Clients: 5")
print("Client Request Accepting..............")
sent = threading.Thread(target=send)
sent.start()
while True:
    server.listen(1)
    clientscok, clientAddress = server.accept()
    Nthread = ClientThread(clientAddress, clientscok,public_key,private_key)
    Nthread.start()
