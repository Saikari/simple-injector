import os
import pytest
import sys
sys.path.append('..')
from . import CertificateGenerator

@pytest.fixture
def cert_gen():
    return CertificateGenerator("outFile", "inputFile", "example.com", "password", "real", "verify")

def test_generate_cert(cert_gen):
    cert_gen.GenerateCert("example.com", "inputFile")
    assert os.path.exists("example.com.key")
    assert os.path.exists("example.com.pem")

def test_generate_pfk(cert_gen):
    cert_gen.GeneratePFK("password", "example.com")
    assert os.path.exists("example.com.pfx")

def test_sign_executable(cert_gen):
    with open("testfile.txt", "w") as f:
        f.write("test")
    cert_gen.SignExecutable("password", "example.com.pfx", "testfile.txt", "signed_testfile.txt")
    assert os.path.exists("signed_testfile.txt")
