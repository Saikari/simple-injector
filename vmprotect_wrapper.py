import ctypes


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

class VMProtectSerialNumberData:
    def __init__(self):
        self.nState = 0
        self.wUserName = (VMP_WCHAR * 256)()
        self.wEMail = (VMP_WCHAR * 256)()
        self.dtExpire = VMProtectDate(0, 0, 0)
        self.bRunningTime = 0
        self.dtMaxBuild = VMProtectDate(0, 0, 0)
        self.nUserDataLength = 0
        self.bUserData = (c_char * 255)()



class VMProtect:
    def __init__(self, dll_path = 'VMProtectSDK64.dll'):
        self.vmprotect_dll = ctypes.CDLL(dll_path)
        self.vmprotect_dll.VMProtectBegin.argtypes = [ctypes.c_char_p]
        self.vmprotect_dll.VMProtectBeginVirtualization.argtypes = [ctypes.c_char_p]
        self.vmprotect_dll.VMProtectBeginMutation.argtypes = [ctypes.c_char_p]
        self.vmprotect_dll.VMProtectBeginUltra.argtypes = [ctypes.c_char_p]
        self.vmprotect_dll.VMProtectBeginVirtualizationLockByKey.argtypes = [ctypes.c_char_p]
        self.vmprotect_dll.VMProtectBeginUltraLockByKey.argtypes = [ctypes.c_char_p]
        self.vmprotect_dll.VMProtectEnd.argtypes = []
        self.vmprotect_dll.VMProtectIsProtected.argtypes = []
        self.vmprotect_dll.VMProtectIsProtected.restype = ctypes.c_bool
        self.vmprotect_dll.VMProtectIsDebuggerPresent.argtypes = [ctypes.c_bool]
        self.vmprotect_dll.VMProtectIsDebuggerPresent.restype = ctypes.c_bool
        self.vmprotect_dll.VMProtectIsVirtualMachinePresent.argtypes = []
        self.vmprotect_dll.VMProtectIsVirtualMachinePresent.restype = ctypes.c_bool
        self.vmprotect_dll.VMProtectIsValidImageCRC.argtypes = []
        self.vmprotect_dll.VMProtectIsValidImageCRC.restype = ctypes.c_bool
        self.vmprotect_dll.VMProtectDecryptStringA.argtypes = [ctypes.c_char_p]
        self.vmprotect_dll.VMProtectDecryptStringA.restype = ctypes.c_char_p
        self.vmprotect_dll.VMProtectDecryptStringW.argtypes = [ctypes.c_wchar_p]
        self.vmprotect_dll.VMProtectDecryptStringW.restype = ctypes.c_wchar_p
        self.vmprotect_dll.VMProtectFreeString.argtypes = [ctypes.c_void_p]
        self.vmprotect_dll.VMProtectFreeString.restype = ctypes.c_bool
        self.vmprotect_dll.VMProtectSetSerialNumber.argtypes = [ctypes.c_char_p]
        self.vmprotect_dll.VMProtectSetSerialNumber.restype = ctypes.c_int
        self.vmprotect_dll.VMProtectGetSerialNumberState.argtypes = []
        self.vmprotect_dll.VMProtectGetSerialNumberState.restype = ctypes.c_int
        self.vmprotect_dll.VMProtectGetSerialNumberData.argtypes = [ctypes.POINTER(VMProtectSerialNumberData), ctypes.c_int]
        self.vmprotect_dll.VMProtectGetSerialNumberData.restype = ctypes.c_bool
        self.vmprotect_dll.VMProtectGetCurrentHWID.argtypes = [ctypes.c_char_p, ctypes.c_int]
        self.vmprotect_dll.VMProtectGetCurrentHWID.restype = ctypes.c_int



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
        return self.vmprotect_dll.VMProtectFreeString(ctypes.c_void_p(id(value)))

    def VMProtectSetSerialNumber(self, serial_number: str) -> int:
        return self.vmprotect_dll.VMProtectSetSerialNumber(serial_number.encode())

    def VMProtectGetSerialNumberState(self) -> int:
        return self.vmprotect_dll.VMProtectGetSerialNumberState()

    def VMProtectGetSerialNumberData(self, data: VMProtectSerialNumberData, size: int) -> bool:
        return self.vmprotect_dll.VMProtectGetSerialNumberData(data, size)

    def VMProtectGetCurrentHWID(self, HWID: str, size: int) -> int:
        return self.vmprotect_dll.VMProtectGetCurrentHWID(HWID.encode(), size)
