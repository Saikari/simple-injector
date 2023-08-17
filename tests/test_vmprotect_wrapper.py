import pytest
from vmprotect_wrapper import VMProtect

@pytest.fixture
def vmprotect():
    return VMProtect()

def test_vmprotect_functions(vmprotect):
    print(vmprotect.vmprotect_dll.__dict__)
    assert vmprotect.vmprotect_dll.__dict__ != None

