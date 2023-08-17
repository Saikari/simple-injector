from os import chdir, rmdir
from ssl import SSLError, create_connection, SSLContext, PROTOCOL_TLS
from random import randint, choice
from string import ascii_letters, digits
from socket import gaierror, timeout
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from OpenSSL import crypto


class CertificateGenerator:
    def __init__(self, outFile, inputFile, domain, password, real, verify):
        self.outFile = outFile
        self.inputFile = inputFile
        self.domain = domain
        self.password = password
        self.real = real
        self.verify = verify
        self.debugging = False
        self.debugWriter = None

    def printDebug(self, format, *args):
        try:
            if self.debugging:
                output = "[DEBUG] " + format % args
                self.debugWriter.write(output)
        except Exception as e:
            print("An error occurred during printDebug:", str(e))

    def VarNumberLength(self, min, max):
        try:
            num = randint(min, max)
            return self.RandStringBytes(num)
        except Exception as e:
            print("An error occurred during VarNumberLength:", str(e))

    @staticmethod
    def RandStringBytes(n):
        try:
            letters = ascii_letters + digits
            return ''.join(choice(letters) for _ in range(n))
        except Exception as e:
            print("An error occurred during RandStringBytes:", str(e))

    def GenerateCert(self, domain, inputFile):
        try:
            rootKey = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            certs, err = self.GetCertificatesPEM(domain + ":443")
            if err is not None:
                chdir("..")
                foldername = inputFile.split(".")
                rmdir(foldername[0])
                raise Exception(f"Error: The domain: {domain} does not exist or "
                                "is not accessible from the host you are compiling on")
            cert = x509.load_pem_x509_certificate(certs.encode(), default_backend())
            self.keyToFile(domain + ".key", rootKey)
            SubjectTemplate = x509.CertificateBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME,
                                   cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
            ])).issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME,
                                   cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
            ])).not_valid_before(cert.not_valid_before).not_valid_after(cert.not_valid_after).serial_number(
                cert.serial_number).public_key(rootKey.public_key()).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True).add_extension(
                x509.KeyUsage(digital_signature=True, key_cert_sign=True, key_encipherment=True,
                              content_commitment=True, data_encipherment=True), critical=True).add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH, x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True).sign(rootKey, hashes.SHA256(), default_backend())
            derBytes = SubjectTemplate.public_bytes(serialization.Encoding.DER)
            self.certToFile(domain + ".pem", derBytes)
        except (SSLError, ConnectionRefusedError, gaierror, timeout) as e:
            print("An error occurred during certificate generation:", str(e))
        except Exception as e:
            print("An error occurred during certificate generation:", str(e))
        else:
            print("Certificate generated successfully.")

    @staticmethod
    def keyToFile(filename, key):
        try:
            with open(filename, "wb") as file:
                file.write(
                    key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
                                      encryption_algorithm=serialization.NoEncryption()))
        except Exception as e:
            print("An error occurred during keyToFile:", str(e))

    @staticmethod
    def certToFile(filename, derBytes):
        try:
            with open(filename, "wb") as file:
                file.write(derBytes)
        except Exception as e:
            print("An error occurred during certToFile:", str(e))

    @staticmethod
    def GetCertificatesPEM(address):
        try:
            conn = create_connection((address, 443))
            context = SSLContext(PROTOCOL_TLS)
            sock = context.wrap_socket(conn, server_hostname=address)
            certs = sock.getpeercert(True)
            sock.close()
            b = b""
            for cert in certs:
                b += cert[1]
            return b.decode(), None
        except (SSLError, ConnectionRefusedError, gaierror, timeout) as e:
            raise Exception(f"Error getting certificates for {address}: {str(e)}")
        except Exception as e:
            print("An error occurred during GetCertificatesPEM:", str(e))

    @staticmethod
    def GeneratePFK(password, domain):
        try:
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 2048)
            cert = crypto.X509()
            cert.get_subject().CN = domain
            cert.set_serial_number(1000)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(key)
            cert.sign(key, 'sha256')
            p12 = crypto.PKCS12()
            p12.set_privatekey(key)
            p12.set_certificate(cert)
            p12.set_ca_certificates([cert])
            p12.set_friendlyname(domain)
            pfx_data = p12.export(password)
            with open(domain + ".pfx", "wb") as file:
                file.write(pfx_data)
        except crypto.Error as e:
            print("An error occurred during GeneratePFK:", str(e))

    @staticmethod
    def SignExecutable(password, pfx, filein, fileout):
        try:
            with open(pfx, 'rb') as f:
                pfx_data = f.read()
            p12 = crypto.load_pkcs12(pfx_data, password)
            signed_data = crypto.sign(p12.get_privatekey(), p12.get_certificate(), open(filein, 'rb').read(), 'sha256')
            with open(fileout, 'wb') as f:
                f.write(signed_data)
        except (crypto.Error, Exception) as e:
            print("An error occurred during SignExecutable:", str(e))

    def Check(self, check):
        try:
            with open(check, 'rb') as f:
                data = f.read()
            p12 = crypto.load_pkcs12(open(self.real, 'rb').read(), self.password)
            private_key = p12.get_privatekey().to_cryptography_key()
            private_key_str = private_key.export_key()
            crypto.verify(p12.get_certificate(), data, private_key_str, 'sha256')
            print("Signature verified successfully.")
        except FileNotFoundError as e:
            print("Error: File not found:", str(e))
        except crypto.Error as e:
            print("Error occurred during signature verification:", str(e))
        except Exception as e:
            print("An unexpected error occurred during signature verification:", str(e))
