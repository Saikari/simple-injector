from os import path
from pytest import fixture
from CertificateGenerator import CertificateGenerator


@fixture
def cert_gen():
    return CertificateGenerator("outFile", "inputFile", "dzen.ru", "password", "real", "verify")


def test_generate_cert(cert_gen):
    cert_gen.GenerateCert("dzen.ru")
    assert path.exists("dzen.ru.key")
    assert path.exists("dzen.ru.pem")


def test_generate_pfk(cert_gen):
    cert_gen.GeneratePFK("password", "dzen.ru")
    assert path.exists("dzen.ru.pfx")


def test_sign_executable(cert_gen):
    with open("testfile.txt", "w") as f:
        f.write("test")
    cert_gen.SignExecutable("password", "dzen.ru.pfx", "testfile.txt", "signed_testfile.txt")
    assert path.exists("signed_testfile.txt")

def test_check_signature_verification(cert_gen):
    # Create a temporary file and sign it
    filein = "testfile.txt"
    fileout = "signed_testfile.txt"
    with open(filein, "w") as f:
        f.write("test data")
    cert_gen.SignExecutable("password", "domain.pfx", filein, fileout)
    # Verify the signature
    cert_gen.real = "dzen.ru.pfx"
    cert_gen.password = "password"
    assert cert_gen.Check(fileout) is True

