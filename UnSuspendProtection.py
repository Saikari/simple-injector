from ctypes import c_size_t, POINTER, wintypes, WinDLL, c_char_p, Structure, c_void_p, c_ulong
from logging import basicConfig, StreamHandler, error, DEBUG, FileHandler, info

basicConfig(level=DEBUG, format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                FileHandler('debug_UnSuspendProtection.log'),
                StreamHandler()
            ]
            )
# Load the kernel32 library
kernel32 = WinDLL('kernel32')


# Define the MEMORY_BASIC_INFORMATION structure
class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ('BaseAddress', c_void_p),
        ('AllocationBase', c_void_p),
        ('AllocationProtect', c_ulong),
        ('RegionSize', c_size_t),
        ('State', c_ulong),
        ('Protect', c_ulong),
        ('Type', c_ulong)
    ]

# Define the function prototype for ResumeThread
ResumeThread = kernel32.ResumeThread
ResumeThread.argtypes = [c_void_p]
ResumeThread.restype = c_ulong

GetModuleHandleA = kernel32.GetModuleHandleA
GetModuleHandleA.argtypes = [c_char_p]
GetModuleHandleA.restype = c_void_p

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = [c_void_p, c_char_p]
GetProcAddress.restype = c_void_p


def GetLibraryProcAddress(libname, procname):
    hModule = GetModuleHandleA(libname.encode())
    if hModule == 0:
        return None
    return GetProcAddress(hModule, procname.encode())


def UnSuspendProtection(hThread):
    suspend_count = ResumeThread(hThread)
    if suspend_count == -1:
        print('[UnSuspendThread] [ERROR] Failed to resume thread')
        error('[UnSuspendThread] [ERROR] Failed to resume thread')
        return False
    else:
        print('[UnSuspendThread] [SUCCESS] Thread resumed')
        info('[UnSuspendThread] [SUCCESS] Thread resumed')
        return True
