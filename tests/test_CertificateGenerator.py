from os import path
from pytest import fixture
from CertificateGenerator import CertificateGenerator


@fixture
def cert_gen():
    return CertificateGenerator("outFile", "inputFile", "digicert.com", "password", "real", "verify")


def test_generate_cert(cert_gen):
    cert_gen.GenerateCert("digicert.com")
    assert path.exists("digicert.com.key")
    assert path.exists("digicert.com.pem")


def test_generate_pfk(cert_gen):
    cert_gen.GeneratePFK("password", "digicert.com")
    assert path.exists("digicert.com.pfx")


def test_sign_executable(cert_gen):
    with open("testfile.bin", "wb") as f:
        f.write(b"test")
    cert_gen.SignExecutable("password", "digicert.com.pfx", "testfile.txt", "signed_testfile.txt")
    assert path.exists("signed_testfile.txt")


def test_check_signature_verification(cert_gen):
    # Create a temporary file and sign it
    filein = "testfile.bin"
    fileout = "signed_testfile.bin"
    with open(filein, "wb") as f:
        f.write(b"test data")
    cert_gen.SignExecutable("password", "digicert.com.pfx", filein, fileout)
    # Verify the signature
    cert_gen.real = "digicert.com.pfx"
    cert_gen.password = "password"
    assert cert_gen.Check(fileout) is True
