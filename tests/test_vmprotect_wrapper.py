import pytest
from vmprotect_wrapper import VMProtect

@pytest.fixture
def vmprotect():
    return VMProtect()

def test_vmprotect_begin(vmprotect):
    marker_name = "test_marker"
    vmprotect.VMProtectBegin(marker_name)
    assert vmprotect.VMProtectIsProtected() == True

def test_vmprotect_begin_virtualization(vmprotect):
    marker_name = "test_marker"
    vmprotect.VMProtectBeginVirtualization(marker_name)
    assert vmprotect.VMProtectIsProtected() == True

def test_vmprotect_begin_mutation(vmprotect):
    marker_name = "test_marker"
    vmprotect.VMProtectBeginMutation(marker_name)
    assert vmprotect.VMProtectIsProtected() == True

def test_vmprotect_begin_ultra(vmprotect):
    marker_name = "test_marker"
    vmprotect.VMProtectBeginUltra(marker_name)
    assert vmprotect.VMProtectIsProtected() == True

def test_vmprotect_end(vmprotect):
    marker_name = "test_marker"
    vmprotect.VMProtectBegin(marker_name)
    assert vmprotect.VMProtectIsProtected() == True

def test_vmprotect_decrypt_string_a(vmprotect):
    string = "encrypted_string"
    encrypted_string = vmprotect.VMProtectDecryptStringA(encrypted_string)
    assert encrypted_string != string
