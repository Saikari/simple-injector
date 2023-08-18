from ctypes import byref, WINFUNCTYPE, c_long, sizeof, c_void_p, c_size_t, cast, POINTER, wintypes, WinDLL, c_char_p, \
    Structure, c_ulong, c_bool
from logging import basicConfig, StreamHandler, error, DEBUG, FileHandler, info

basicConfig(level=DEBUG, format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                FileHandler('debug_SuspendProtection.log'),
                StreamHandler()
            ]
            )
# Load the kernel32 library
kernel32 = WinDLL('kernel32')


class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize", c_ulong),
        ("cntUsage", c_ulong),
        ("th32ThreadID", c_ulong),
        ("th32OwnerProcessID", c_ulong),
        ("tpBasePri", c_long),
        ("tpDeltaPri", c_long),
        ("dwFlags", c_ulong),
    ]


class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("AllocationProtect", c_ulong),
        ("RegionSize", c_size_t),
        ("State", c_ulong),
        ("Protect", c_ulong),
        ("Type", c_ulong)
    ]


# Define the function prototype for VirtualQueryEx
VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [c_void_p, c_void_p, POINTER(MEMORY_BASIC_INFORMATION), c_size_t]
VirtualQueryEx.restype = c_size_t

# Define the function prototype OpenThread
OpenThread = kernel32.OpenThread
OpenThread.argtypes = [c_ulong, c_bool, c_ulong]
OpenThread.restype = c_void_p

# Define the function prototypes
Thread32First = kernel32.Thread32First
Thread32First.argtypes = [wintypes.HANDLE, POINTER(THREADENTRY32)]
Thread32First.restype = wintypes.BOOL

Thread32Next = kernel32.Thread32Next
Thread32Next.argtypes = [wintypes.HANDLE, POINTER(THREADENTRY32)]
Thread32Next.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

# Define the function prototype SuspendThread
SuspendThread = kernel32.SuspendThread
SuspendThread.argtypes = [wintypes.HANDLE]
SuspendThread.restype = wintypes.DWORD

# Define the function prototype CreateToolhelp32Snapshot
CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [c_ulong, c_ulong]
CreateToolhelp32Snapshot.restype = wintypes.HANDLE

_NtQueryInformationThread = WINFUNCTYPE(wintypes.DWORD, wintypes.HANDLE, wintypes.DWORD, c_void_p, wintypes.DWORD,
                                        POINTER(wintypes.DWORD))

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


def SuspendProtection(hProcess, pid, protAddr):
    if pid == 0 or protAddr == 0:
        print('[SuspendProtection] [ERROR] Invalid pid or protAddr')
        error('[SuspendProtection] [ERROR] Invalid pid or protAddr')
        return False

    te32 = THREADENTRY32()
    hThreadSnap = CreateToolhelp32Snapshot(0x00000004, 0)
    te32.dwSize = sizeof(te32)
    Thread32First(hThreadSnap, byref(te32))
    while Thread32Next(hThreadSnap, byref(te32)):
        if te32.th32OwnerProcessID == pid:
            threadInfo = c_void_p()
            retLen = wintypes.ULONG()
            NtQueryInformationThread = _NtQueryInformationThread(
                GetLibraryProcAddress("ntdll.dll", "NtQueryInformationThread"))
            if NtQueryInformationThread is None:
                print('[SuspendProtection] [ERROR] Failed to get NtQueryInformationThread')
                error('[SuspendProtection] [ERROR] Failed to get NtQueryInformationThread')
                return False

            hThread = OpenThread(0x1F03FF, 0, te32.th32ThreadID)
            ntqiRet = NtQueryInformationThread(hThread, 9, byref(threadInfo), sizeof(c_void_p), byref(retLen))

            mbi = MEMORY_BASIC_INFORMATION()
            if VirtualQueryEx(hProcess, threadInfo, byref(mbi), sizeof(mbi)):
                baseAddress = cast(mbi.AllocationBase, c_void_p).value
                if baseAddress == protAddr:
                    SuspendThread(hThread)
                    print('[SuspendProtection] [SUCCESS] Thread suspended')
                    info('[SuspendProtection] [SUCCESS] Thread suspended')
                    return hThread

    CloseHandle(hThreadSnap)
    print('[SuspendProtection] [WARNING] Thread not found')
    error('[SuspendProtection] [WARNING] Thread not found')
    return False
