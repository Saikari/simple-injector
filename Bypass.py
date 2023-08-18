from ctypes import byref, windll, sizeof, Structure, WinDLL, \
    c_void_p, c_char_p, c_wchar_p, c_ulong, c_long, c_bool, wintypes, FormatError, \
    c_int, c_uint, c_size_t, c_ulonglong, POINTER, create_string_buffer
from time import sleep
from typing import Optional
from Injector import Injector
from traceback import format_exc
import win32process
import win32security, win32api, win32con, pywintypes
from Inject import Inject
from SuspendProtection import SuspendProtection
from UnSuspendProtection import UnSuspendProtection
# brainfuck
from ntsecuritycon import TokenSessionId, TokenSandBoxInert, TokenType, TokenImpersonationLevel, \
    TokenVirtualizationEnabled, TokenVirtualizationAllowed, TokenHasRestrictions, TokenElevationType, TokenUIAccess, \
    TokenUser, TokenOwner, TokenGroups, TokenRestrictedSids, TokenPrivileges, TokenPrimaryGroup, TokenSource, \
    TokenDefaultDacl, TokenStatistics, TokenOrigin, TokenLinkedToken, TokenLogonSid, TokenElevation, \
    TokenIntegrityLevel, TokenMandatoryPolicy, SE_ASSIGNPRIMARYTOKEN_NAME, SE_BACKUP_NAME, SE_CREATE_PAGEFILE_NAME, \
    SE_CREATE_TOKEN_NAME, SE_DEBUG_NAME, SE_LOAD_DRIVER_NAME, SE_MACHINE_ACCOUNT_NAME, SE_RESTORE_NAME, \
    SE_SHUTDOWN_NAME, SE_TAKE_OWNERSHIP_NAME, SE_TCB_NAME
from logging import info, error


class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", c_ulonglong),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]


class MODULEENTRY32(Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", wintypes.LPVOID),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.CHAR * 256),
        ("szExePath", wintypes.CHAR * 260)
    ]


class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD)
    ]


# Load the ntdll library
ntdll = WinDLL('ntdll')

# Define the function prototype
NtQueryInformationThread = ntdll.NtQueryInformationThread
NtQueryInformationThread.argtypes = [
    wintypes.HANDLE,
    c_int,
    c_void_p,
    c_ulong,
    POINTER(c_ulong),
]
NtQueryInformationThread.restype = c_long

# Load the user32 library
user32 = windll.user32

# Define the function prototype for FindWindowW
FindWindowW = user32.FindWindowW
FindWindowW.argtypes = [c_wchar_p, c_wchar_p]
FindWindowW.restype = c_void_p

# Load the kernel32 library
kernel32 = windll.kernel32


GetLastError = kernel32.GetLastError
# Set the argument types and return type for the GetLastError function
GetLastError.argtypes = []
GetLastError.restype = c_ulong
# Define the function prototype for TerminateProcess
TerminateProcess = kernel32.TerminateProcess
TerminateProcess.argtypes = [wintypes.HANDLE, c_uint]
TerminateProcess.restype = wintypes.BOOL
# Define the function prototype OpenThread
OpenThread = kernel32.OpenThread
OpenThread.argtypes = [c_ulong, c_bool, c_ulong]
OpenThread.restype = c_void_p
# Define the function prototype CloseHandle
CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

# Define the function prototype CreateToolhelp32Snapshot
CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [c_ulong, c_ulong]
CreateToolhelp32Snapshot.restype = wintypes.HANDLE

# Define the function prototype SuspendThread
SuspendThread = kernel32.SuspendThread
SuspendThread.argtypes = [wintypes.HANDLE]
SuspendThread.restype = wintypes.DWORD

# Define the function prototype Thread32First
Thread32First = kernel32.Thread32First
Thread32First.argtypes = [wintypes.HANDLE, POINTER(THREADENTRY32)]
Thread32First.restype = wintypes.BOOL

# Define the function prototype Thread32Next
Thread32Next = kernel32.Thread32Next
Thread32Next.argtypes = [wintypes.HANDLE, POINTER(THREADENTRY32)]
Thread32Next.restype = wintypes.BOOL


class Bypass(Injector):
    def __init__(self):
        super().__init__()

    PROCESS_ALL_ACCESS = 0x1FFFFF

    # PROCESS_ALL_ACCESS = 0x0010
    @staticmethod
    def Patch(address: c_void_p, data: bytes, size: c_size_t, handle: wintypes.HANDLE) -> bool:
        oldProtect = wintypes.DWORD(0)
        if not windll.kernel32.VirtualProtectEx(handle, address, size, 0x40, byref(oldProtect)):
            return False
        # Create a buffer of the appropriate size
        buffer = create_string_buffer(data, len(data))
        if not windll.kernel32.WriteProcessMemory(handle, address, byref(buffer), size, None):  # data, size, None):
            return False
        if not windll.kernel32.VirtualProtectEx(handle, address, size, oldProtect, byref(oldProtect)):
            return False
        return True

    @staticmethod
    def GetLibraryProcAddress(library: str, function: str):
        hModule = windll.kernel32.GetModuleHandleA(library.encode())
        if not hModule:
            return None
        return windll.kernel32.GetProcAddress(hModule, function.encode())

    @staticmethod
    def GetModuleAddress(module: str, pid: int) -> Optional[int]:
        hSnapshot = windll.kernel32.CreateToolhelp32Snapshot(0x00000008, pid)
        if hSnapshot == -1:
            return None
        me32 = MODULEENTRY32()
        me32.dwSize = sizeof(me32)
        if not windll.kernel32.Module32First(hSnapshot, byref(me32)):
            windll.kernel32.CloseHandle(hSnapshot)
            return None
        while True:
            if me32.szModule.decode().lower() == module.lower():
                windll.kernel32.CloseHandle(hSnapshot)
                return me32.modBaseAddr
            if not windll.kernel32.Module32Next(hSnapshot, byref(me32)):
                break
        windll.kernel32.CloseHandle(hSnapshot)
        return None

    @staticmethod
    def Bedge(ms: int) -> None:
        sleep(ms / 1000.0)

    @staticmethod
    def get_extra_privs() -> None:
        # Try to give ourselves some extra privs (only works if we're admin):
        # SeBackupPrivilege   - so we can read anything
        # SeDebugPrivilege    - so we can find out about other processes (otherwise OpenProcess will fail for some)
        # SeSecurityPrivilege - ??? what does this do?

        # Problem: Vista+ support "Protected" processes, e.g. audiodg.exe.  We can't see info about these.
        # Interesting post on why Protected Process aren't really secure anyway: http://www.alex-ionescu.com/?p=34

        th = win32security.OpenProcessToken(win32api.GetCurrentProcess(),
                                            win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
        privs = win32security.GetTokenInformation(th, TokenPrivileges)
        newprivs = []
        for privtuple in privs:
            if privtuple[0] == win32security.LookupPrivilegeValue(None, "SeBackupPrivilege") or \
                    privtuple[0] == win32security.LookupPrivilegeValue(None, "SeDebugPrivilege") or \
                    privtuple[0] == win32security.LookupPrivilegeValue(None, "SeSecurityPrivilege"):
                info("Added privilege " + str(privtuple[0]))
                newprivs.append((privtuple[0], 2))  # SE_PRIVILEGE_ENABLED
            else:
                info("Set privilege " + str(privtuple[0]))
                newprivs.append((privtuple[0], privtuple[1]))

        # Adjust privs
        privs = tuple(newprivs)
        win32security.AdjustTokenPrivileges(th, False, privs)

    @staticmethod
    def Attack(dll_path, process_name, process_window_name, pid) -> bool:
        print(dll_path)
        print(process_name)
        print(process_window_name)
        Bypass.get_extra_privs()
        isInjected = False
        hwnd = None
        while not isInjected:
            while hwnd is None:
                hwnd = FindWindowW(process_window_name, None)
                if hwnd == 0:
                    isInjected = False
                    Bypass.Bedge(1000)
            print(f'Proc pid = {pid}')
            info(f'Proc pid = {pid}')
            print(f'Allowed access to remote proc = {win32con.MAXIMUM_ALLOWED:#X}')
            info(f'Allowed access to remote proc = {win32con.MAXIMUM_ALLOWED:#X}')
            handle = OpenProcess(Bypass.PROCESS_ALL_ACCESS, False, pid)
            while handle is None:
                handle = OpenProcess(Bypass.PROCESS_ALL_ACCESS, False, pid)
                Bypass.Bedge(1000)
            print(f'Handle {handle}')
            info(f'Handle {handle}')
            if not handle:
                last_error = GetLastError()
                print(f'Handle error {last_error}: {FormatError(last_error)}')
                error(f'Handle error {last_error}: {FormatError(last_error)}')

            # Restore bytes of these hooked function
            try:
                if Bypass.GetLibraryProcAddress("ntdll.dll", "LdrInitializeThunk"):
                    Bypass.Patch(Bypass.GetLibraryProcAddress("ntdll.dll", "LdrInitializeThunk"),
                                 b"\x40\x53\x48\x83\xEC\x20", c_size_t(6), handle)
                    print("Applied NTDLL.DLL Patch 1")
                else:
                    print("Failed getting GetLibraryProcAddress from NTDLL.DLL")
                if Bypass.GetLibraryProcAddress("ntdll.dll", "NtQueryAttributesFile"):
                    Bypass.Patch(Bypass.GetLibraryProcAddress("ntdll.dll", "NtQueryAttributesFile"),
                                 b"\x4C\x8B\xD1\xB8\x3D\x00\x00\x00", c_size_t(8), handle)
                    print("Applied NTDLL.DLL Patch 2")
                else:
                    print("Failed getting NtQueryAttributesFile from NTDLL.DLL")
            except Exception as e:
                print(f'Error during patching: {format_exc()}')
            try:
                split_result = process_name.split(".")
                process_name_joined = ".".join(split_result[:-1])
                process_dll_main_addr = Bypass.GetModuleAddress(f"{process_name_joined}.dll", pid)
                if process_dll_main_addr is None:
                    process_dll_main_addr = Bypass.GetModuleAddress(f"{process_name_joined}.exe", pid)
                if process_dll_main_addr == 0:
                    print(f"{process_name_joined}.dll not found!")
                    return isInjected
                hThread = SuspendProtection(handle, pid, process_dll_main_addr)
                if hThread:
                    if not isInjected:
                        isInjected = Inject(handle, dll_path)
                    UnSuspendProtection(hThread)
                    CloseHandle(hThread)
                    print('[FINAL] Terminating Python 3 since DLL Injection Job Is Done.')
                    TerminateProcess(wintypes.HANDLE(-1), 0)
                else:
                    print('Didn\'t suspend protection')
            except Exception as e:
                print(f'Error: {format_exc()}')
            Bypass.Bedge(20)
        return isInjected
