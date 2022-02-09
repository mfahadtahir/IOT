import socket
import ast
import json
import hashlib  # Certificate to create session Key
from OpenSSL import crypto, SSL
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 10286        # Port to listen on (non-privileged ports are > 1023)

def cert_gen(
        emailAddress="emailAddress",
        commonName="commonName",
        countryName="NT",
        localityName="localityName",
        stateOrProvinceName="stateOrProvinceName",
        organizationName="organizationName",
        organizationUnitName="organizationUnitName",
        serialNumber=0,
        validityStartInSeconds=0,
        validityEndInSeconds=10*365*24*60*60,
        KEY_FILE="private.key",
        CERT_FILE="selfsigned.crt"):
    # can look at generated file using openssl:
    # openssl x509 -inform pem -in selfsigned.crt -noout -text
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateOrProvinceName
    cert.get_subject().L = localityName
    cert.get_subject().O = organizationName
    cert.get_subject().OU = organizationUnitName
    cert.get_subject().CN = commonName
    cert.get_subject().emailAddress = emailAddress
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open("./certificates/"+CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(
            crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))



def hash_file(filename):
    """"This function returns the SHA-1 hash of the file passed into it"""
    # make a hash object
    h = hashlib.sha1()
    # open file for reading in binary mode
    with open(filename, 'rb') as file:
        # loop till the end of the file
        chunk = 0
        while chunk != b'':
            # read only 1024 bytes at a time
            chunk = file.read(1024)
            h.update(chunk)
    # return the hex representation of digest
    return h.hexdigest()


# message = hash_file("selfsigned.crt")
# print(message)





def startListening():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                # while True:
                data = conn.recv(2048)
                data = int.from_bytes(data, "little")
                print('Server Recieved: ', data)
                if(data[0] == b'unotron'):
                    print("Network verified\nWelcome to Unotron!")
                    conn.sendall(b'Secret Data : ************')
                else:
                    conn.sendall(b'Sorry, you are outside the Network...')
                print("user does not exist is lists, cancelling request...")
                conn.sendall(b'Sorry unauthorized user')



def batch_Cert_gen(num=5):
    data = readJSON("freeCertificates.json")
    till = len(data)
    for x in range(till, till + num):
        print(str(x)+".crt")
        cert_gen(CERT_FILE=str(x)+".crt")
        data.append(x)
    writeJSON("freeCertificates.json",data)
    


def assignCertificate(MAC):
    data = readJSON("assignedCertificates.json")
    data[MAC] = getFreeCert()
    writeJSON("assignedCertificates.json",data)

def getFreeCert():
    data = readJSON("freeCertificates.json")
    assign = data.pop(0)
    writeJSON("freeCertificates.json", data)
    print(assign)
    return assign


# Utilities
def writeJSON(fileName, data):
    json_object = json.dumps(data, indent = 4)
    with open(fileName, "w") as outfile:
        return outfile.write(json_object)

def readJSON(filename):
    with open(filename, 'r') as openfile:
        json_object = json.load(openfile)
        return json_object



if __name__ == "__main__":
    print("Hello World!")
    # batch_Cert_gen()
    assignCertificate(126)

    # print(getFreeCert())
    # storeData('234')
    # data = readJSON("freeCertificates.json")
    # data = 23
    # writeJSON("assignedCertificates.json", data)

