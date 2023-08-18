from ctypes import c_size_t, cast, byref, c_long, GetLastError, POINTER, \
    WinDLL, c_char_p, Structure, c_void_p, c_ulong, \
    create_string_buffer, wintypes, CDLL, c_uint, CFUNCTYPE
from logging import error, info, debug
import ctypes

# Load the kernel32 library
kernel32 = CDLL('kernel32')

# Define the necessary constants and types
MAX_PATH = 260
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04





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


# Define the function prototypes
Thread32First = kernel32.Thread32First
Thread32First.argtypes = [wintypes.HANDLE, POINTER(THREADENTRY32)]
Thread32First.restype = wintypes.BOOL

Thread32Next = kernel32.Thread32Next
Thread32Next.argtypes = [wintypes.HANDLE, POINTER(THREADENTRY32)]
Thread32Next.restype = wintypes.BOOL

GetFullPathNameA = kernel32.GetFullPathNameA
GetFullPathNameA.argtypes = [c_char_p, wintypes.DWORD, c_char_p, POINTER(c_char_p)]
GetFullPathNameA.restype = wintypes.DWORD

GetFileAttributesA = kernel32.GetFileAttributesA
GetFileAttributesA.argtypes = [c_char_p]
GetFileAttributesA.restype = wintypes.DWORD

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [wintypes.HANDLE, c_void_p, c_size_t, wintypes.DWORD, wintypes.DWORD]
VirtualAllocEx.restype = c_void_p

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [wintypes.HANDLE, c_void_p, c_void_p, c_size_t, POINTER(c_size_t)]
WriteProcessMemory.restype = wintypes.BOOL

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = [wintypes.HANDLE, c_void_p, c_size_t, c_void_p, c_void_p, wintypes.DWORD,
                               POINTER(wintypes.DWORD)]
CreateRemoteThread.restype = wintypes.HANDLE

WaitForSingleObject = kernel32.WaitForSingleObject
WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
WaitForSingleObject.restype = wintypes.DWORD

GetExitCodeThread = kernel32.GetExitCodeThread
GetExitCodeThread.argtypes = [wintypes.HANDLE, POINTER(wintypes.DWORD)]
GetExitCodeThread.restype = wintypes.BOOL

VirtualFreeEx = kernel32.VirtualFreeEx
VirtualFreeEx.argtypes = [wintypes.HANDLE, c_void_p, c_size_t, wintypes.DWORD]
VirtualFreeEx.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL


# Define the ReflectiveLoader function


def Inject(hProcess, dllName) -> bool:
    buffer = create_string_buffer(MAX_PATH)
    if not GetFullPathNameA(dllName.encode(), MAX_PATH, buffer, None):
        print(f"[Inject] [ERROR] GetFullPathNameA failed {GetLastError()}")
        error(f"[Inject] [ERROR] GetFullPathNameA failed {GetLastError()}")
        return False

    if GetFileAttributesA(buffer) == 0xFFFFFFFF:
        print(f"[Inject] [ERROR] DLL not found {dllName}")
        error(f"[Inject] [ERROR] DLL not found {dllName}")
        return False

    pPath = VirtualAllocEx(
        hProcess,
        c_void_p(0),
        c_size_t(0x1000),
        c_uint(MEM_COMMIT | MEM_RESERVE),
        c_uint(PAGE_READWRITE)
    )
    if not pPath:
        print(f"[Inject] [ERROR] VirtualAllocEx failed {GetLastError()}")
        error(f"[Inject] [ERROR] VirtualAllocEx failed {GetLastError()}")
        return False
    written = c_size_t()
    if not WriteProcessMemory(
            hProcess,
            pPath,
            buffer,
            c_size_t(len(buffer.value)),
            byref(written)):
        print(f"[Inject] [ERROR] WriteProcessMemory failed {GetLastError()}")
        error(f"[Inject] [ERROR] WriteProcessMemory failed {GetLastError()}")
        kernel32.VirtualFreeExA(hProcess, pPath, 0, MEM_RELEASE)
        return False
    print(f"[Inject] [DEBUG] {written.value} bytes written to process {hProcess}")
    debug(f"[Inject] [DEBUG] {written.value} bytes written to process {hProcess}")
    hThread = CreateRemoteThread(hProcess, None, 0, cast(kernel32.LoadLibraryA, c_void_p), pPath, 0, None)
    if not hThread:
        print(f"[Inject] [ERROR] CreateRemoteThread failed {GetLastError()}")
        error(f"[Inject] [ERROR] CreateRemoteThread failed {GetLastError()}")
        kernel32.VirtualFreeExA(hProcess, pPath, 0, MEM_RELEASE)
        return False
    print(f"[Inject] [DEBUG] Waiting for thread {hThread} to finish")
    debug(f"[Inject] [DEBUG] Waiting for thread {hThread} to finish")
    WaitForSingleObject(hThread, -1)
    exitCode = wintypes.DWORD()
    GetExitCodeThread(hThread, byref(exitCode))
    debug(f"[Inject] [DEBUG] Exit code: {exitCode}")
    print(f"[Inject] [DEBUG] Exit code: {exitCode}")
    if exitCode == 0:
        info(f"[Inject] [SUCCESS] Success Inject! Exit code: {exitCode}")
        print(f"[Inject] [SUCCESS] Success Inject! Exit code: {exitCode}")
    else:
        info(f"[Inject] [WARNING] Injection succeeded but exit code is {exitCode}.")
        print(f"[Inject] [WARNING] Injection succeeded but exit code is {exitCode}.")
    kernel32.VirtualFreeEx(hProcess, pPath, 0, MEM_RELEASE)
    CloseHandle(hThread)
    return True