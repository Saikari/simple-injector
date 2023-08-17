from ctypes import byref, c_wchar_p, c_uint8, c_char, c_int, c_void_p, c_wchar, c_int32, POINTER, c_char_p, Structure, \
    CDLL, c_bool
import platform

class VMProtectSerialStateFlags:
    SERIAL_STATE_SUCCESS = 0x0
    SERIAL_STATE_FLAG_CORRUPTED = 0x1
    SERIAL_STATE_FLAG_INVALID = 0x2
    SERIAL_STATE_FLAG_BLACKLISTED = 0x4
    SERIAL_STATE_FLAG_DATE_EXPIRED = 0x8
    SERIAL_STATE_FLAG_RUNNING_TIME_OVER = 0x10
    SERIAL_STATE_FLAG_BAD_HWID = 0x20
    SERIAL_STATE_FLAG_MAX_BUILD_EXPIRED = 0x40


class VMProtectActivationFlags:
    ACTIVATION_OK = 0
    ACTIVATION_SMALL_BUFFER = 1
    ACTIVATION_NO_CONNECTION = 2
    ACTIVATION_BAD_REPLY = 3
    ACTIVATION_BANNED = 4
    ACTIVATION_CORRUPTED = 5
    ACTIVATION_BAD_CODE = 6
    ACTIVATION_ALREADY_USED = 7
    ACTIVATION_SERIAL_UNKNOWN = 8
    ACTIVATION_EXPIRED = 9
    ACTIVATION_NOT_AVAILABLE = 10


class VMProtectDate:
    def __init__(self, wYear, bMonth, bDay):
        self.wYear = wYear
        self.bMonth = bMonth
        self.bDay = bDay


class VMProtectSerialNumberData(Structure):
    _fields_ = [
        ("nState", c_int32),
        ("wUserName", c_wchar * 256),
        ("wEMail", c_wchar * 256),
        ("dtExpire", VMProtectDate),
        ("bRunningTime", c_int32),
        ("dtMaxBuild", VMProtectDate),
        ("nUserDataLength", c_uint8),
        ("bUserData", c_char * 255)
    ]


class VMProtectActivation:
    def __init__(self):
        os_name = platform.system()
        arch = platform.architecture()[0]
        
        if os_name == 'Windows':
            if arch == '32bit':
                dll_path = 'Windows/VMProtectSDK32.dll'
            elif arch == '64bit':
                dll_path = 'Windows/VMProtectSDK64.dll'
            else:
                raise Exception("Unsupported architecture: " + arch)
        elif os_name == 'Darwin':
            dll_path = 'OSX/libVMProtectSDK.dylib'
        elif os_name == 'Linux':
            if arch == '32bit':
                dll_path = 'Linux/libVMProtectSDK32.so'
            elif arch == '64bit':
                dll_path = 'Linux/libVMProtectSDK64.so'
            else:
                raise Exception("Unsupported architecture: " + arch)
        else:
            raise Exception("Unsupported operating system: " + os_name)
        self.vmprotect_dll = CDLL(dll_path)
        self.vmprotect_dll.VMProtectSetSerialNumber.argtypes = [c_char_p]
        self.vmprotect_dll.VMProtectSetSerialNumber.restype = c_int
        self.vmprotect_dll.VMProtectGetSerialNumberState.argtypes = []
        self.vmprotect_dll.VMProtectGetSerialNumberState.restype = c_int
        self.vmprotect_dll.VMProtectGetSerialNumberData.argtypes = [POINTER(VMProtectSerialNumberData), c_int]
        self.vmprotect_dll.VMProtectGetSerialNumberData.restype = c_bool
        self.vmprotect_dll.VMProtectGetCurrentHWID.argtypes = [c_char_p, c_int]
        self.vmprotect_dll.VMProtectGetCurrentHWID.restype = c_int

    def VMProtectGetCurrentHWID(self, HWID: str, size: int) -> int:
        return self.vmprotect_dll.VMProtectGetCurrentHWID(HWID.encode(), size)

    def VMProtectSetSerialNumber(self, serial_number: str) -> int:
        return self.vmprotect_dll.VMProtectSetSerialNumber(serial_number.encode())

    def VMProtectGetSerialNumberState(self) -> int:
        return self.vmprotect_dll.VMProtectGetSerialNumberState()

    def VMProtectGetSerialNumberData(self, data: VMProtectSerialNumberData, size: int) -> bool:
        return self.vmprotect_dll.VMProtectGetSerialNumberData(byref(data), size)


class VMProtect:
    def __init__(self):
        os_name = platform.system()
        arch = platform.architecture()[0]
        if os_name == 'Windows':
            if arch == '32bit':
                dll_path = 'Windows/VMProtectSDK32.dll'
            elif arch == '64bit':
                dll_path = 'Windows/VMProtectSDK64.dll'
            else:
                raise Exception("Unsupported architecture: " + arch)
        elif os_name == 'Darwin':
            dll_path = 'OSX/libVMProtectSDK.dylib'
        elif os_name == 'Linux':
            if arch == '32bit':
                dll_path = 'Linux/libVMProtectSDK32.so'
            elif arch == '64bit':
                dll_path = 'Linux/libVMProtectSDK64.so'
            else:
                raise Exception("Unsupported architecture: " + arch)
        else:
            raise Exception("Unsupported operating system: " + os_name)
        self.vmprotect_dll = CDLL(dll_path)
        self.vmprotect_dll.VMProtectBegin.argtypes = [c_char_p]
        self.vmprotect_dll.VMProtectBeginVirtualization.argtypes = [c_char_p]
        self.vmprotect_dll.VMProtectBeginMutation.argtypes = [c_char_p]
        self.vmprotect_dll.VMProtectBeginUltra.argtypes = [c_char_p]
        self.vmprotect_dll.VMProtectBeginVirtualizationLockByKey.argtypes = [c_char_p]
        self.vmprotect_dll.VMProtectBeginUltraLockByKey.argtypes = [c_char_p]
        self.vmprotect_dll.VMProtectEnd.argtypes = []
        self.vmprotect_dll.VMProtectIsProtected.argtypes = []
        self.vmprotect_dll.VMProtectIsProtected.restype = c_bool
        self.vmprotect_dll.VMProtectIsDebuggerPresent.argtypes = [c_bool]
        self.vmprotect_dll.VMProtectIsDebuggerPresent.restype = c_bool
        self.vmprotect_dll.VMProtectIsVirtualMachinePresent.argtypes = []
        self.vmprotect_dll.VMProtectIsVirtualMachinePresent.restype = c_bool
        self.vmprotect_dll.VMProtectIsValidImageCRC.argtypes = []
        self.vmprotect_dll.VMProtectIsValidImageCRC.restype = c_bool
        self.vmprotect_dll.VMProtectDecryptStringA.argtypes = [c_char_p]
        self.vmprotect_dll.VMProtectDecryptStringA.restype = c_char_p
        self.vmprotect_dll.VMProtectDecryptStringW.argtypes = [c_wchar_p]
        self.vmprotect_dll.VMProtectDecryptStringW.restype = c_wchar_p
        self.vmprotect_dll.VMProtectFreeString.argtypes = [c_void_p]
        self.vmprotect_dll.VMProtectFreeString.restype = c_bool

    def VMProtectBegin(self, marker_name: str) -> None:
        self.vmprotect_dll.VMProtectBegin(marker_name.encode())

    def VMProtectBeginVirtualization(self, marker_name: str) -> None:
        self.vmprotect_dll.VMProtectBeginVirtualization(marker_name.encode())

    def VMProtectBeginMutation(self, marker_name: str) -> None:
        self.vmprotect_dll.VMProtectBeginMutation(marker_name.encode())

    def VMProtectBeginUltra(self, marker_name: str) -> None:
        self.vmprotect_dll.VMProtectBeginUltra(marker_name.encode())

    def VMProtectBeginVirtualizationLockByKey(self, marker_name: str) -> None:
        self.vmprotect_dll.VMProtectBeginVirtualizationLockByKey(marker_name.encode())

    def VMProtectBeginUltraLockByKey(self, marker_name: str) -> None:
        self.vmprotect_dll.VMProtectBeginUltraLockByKey(marker_name.encode())

    def VMProtectEnd(self) -> None:
        self.vmprotect_dll.VMProtectEnd()

    def VMProtectIsProtected(self) -> bool:
        return self.vmprotect_dll.VMProtectIsProtected()

    def VMProtectIsDebuggerPresent(self, check_kernel_mode: bool = False) -> bool:
        return self.vmprotect_dll.VMProtectIsDebuggerPresent(check_kernel_mode)

    def VMProtectIsVirtualMachinePresent(self) -> bool:
        return self.vmprotect_dll.VMProtectIsVirtualMachinePresent()

    def VMProtectIsValidImageCRC(self) -> bool:
        return self.vmprotect_dll.VMProtectIsValidImageCRC()

    def VMProtectDecryptStringA(self, value: str) -> str:
        return self.vmprotect_dll.VMProtectDecryptStringA(value.encode()).decode()

    def VMProtectDecryptStringW(self, value: str) -> str:
        return self.vmprotect_dll.VMProtectDecryptStringW(value.encode()).decode()

    def VMProtectFreeString(self, value: str) -> bool:
        return self.vmprotect_dll.VMProtectFreeString(c_void_p(id(value)))
