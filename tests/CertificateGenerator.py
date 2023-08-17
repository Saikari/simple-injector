from ssl import SSLError, create_default_context, CERT_NONE
from random import randint, choice
from string import ascii_letters, digits
from OpenSSL import crypto
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12
from logging import basicConfig, Formatter, StreamHandler, getLogger, INFO, DEBUG, FileHandler
from socket import create_connection, gaierror, timeout

basicConfig(level=DEBUG, filename='certificate_generator.log', filemode='w',
            format='%(asctime)s - %(levelname)s - %(message)s')


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

        # Create logger
        self.logger = getLogger(__name__)
        self.logger.setLevel(DEBUG)

        # Create console handler with a higher log level
        consoleHandler = StreamHandler()
        consoleHandler.setLevel(INFO)

        # Create file handler which logs even debug messages
        fileHandler = FileHandler('certificate_generator.log')
        fileHandler.setLevel(DEBUG)

        # Create formatter and add it to the handlers
        formatter = Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        consoleHandler.setFormatter(formatter)
        fileHandler.setFormatter(formatter)

        # Add the handlers to the logger
        self.logger.addHandler(consoleHandler)
        self.logger.addHandler(fileHandler)

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

    def GeneratePKey(self, domain) -> crypto.PKey:
        rootKey = crypto.PKey()
        rootKey.generate_key(crypto.TYPE_RSA, 4096)
        self.keyToFile(domain + ".key", rootKey)
        return rootKey

    def GenerateCert(self, domain, rootKey=None) -> crypto.X509:
        try:
            certs, err = self.GetCertificatesPEM(domain + ":443")
            if err is not None:
                raise Exception(f"Error: The domain: {domain} does not exist or "
                                f"is not accessible from the host you are compiling on. {err}")
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, certs)
            if rootKey is None:
                rootKey = self.GeneratePKey(domain)
            subject = crypto.X509Req()
            for component in cert.get_subject().get_components():
                setattr(subject.get_subject(), component[0].decode(), component[1].decode())
            subject.set_pubkey(rootKey)
            subject.sign(rootKey, 'sha256')
            issuer = subject
            cert = crypto.X509()
            cert.set_subject(subject.get_subject())
            cert.set_issuer(issuer.get_subject())
            cert.set_pubkey(subject.get_pubkey())
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
            cert.set_serial_number(1000)
            cert.sign(rootKey, 'sha256')
            derBytes = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
            self.certToFile(domain + ".pem", derBytes)
            self.logger.info("Certificate generated successfully.")
            self.logger.debug("Certificate details: %s", str(cert))
            return cert
        except (SSLError, ConnectionRefusedError) as e:
            self.logger.error("An error occurred during certificate generation: %s", str(e))
        except Exception as e:
            self.logger.error("An error occurred during certificate generation: %s", str(e))

    @staticmethod
    def keyToFile(filename, key):
        try:
            with open(filename, "wb") as file:
                file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
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
            context = create_default_context()  # SSLContext(PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = CERT_NONE
            with create_connection((address.split(':')[0], 443)) as sock:
                with context.wrap_socket(sock, server_hostname=address.split(':')[0]) as ssock:
                    cert = ssock.getpeercert(True)
            return crypto.dump_certificate(crypto.FILETYPE_PEM,
                                           crypto.load_certificate(crypto.FILETYPE_ASN1, cert)), None
        except (gaierror, timeout, SSLError, crypto.Error) as e:
            raise Exception(f"Error getting certificates for {address}: {str(e)}")

    def GeneratePFK(self, password, domain) -> crypto.PKCS12:
        try:
            key = self.GeneratePKey(domain)
            cert = self.GenerateCert(domain, key)
            p12 = crypto.PKCS12()
            p12.set_privatekey(key)
            p12.set_certificate(cert)
            p12.set_ca_certificates([cert])
            p12.set_friendlyname(domain.encode())
            pfx_data = p12.export(password.encode())
            with open(domain + ".pfx", "wb") as file:
                file.write(pfx_data)
            return p12
        except crypto.Error as e:
            print("An error occurred during GeneratePFK:", str(e))

    @staticmethod
    def SignExecutable(password, pfx, filein, fileout):
        try:
            with open(pfx, 'rb') as f:
                pfx_data = f.read()
            p12 = load_pkcs12(pfx_data, password.encode())
            private_key = p12.key
            with open(filein, 'rb') as f:
                data = f.read()
            signature = private_key.sign(
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            with open(fileout, 'wb') as f:
                f.write(data + signature)
        except Exception as e:
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
