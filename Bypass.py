import ctypes
from ctypes import wintypes
import os
import sys
import time
from typing import Optional
class Injector:
    @staticmethod
    def SuspendProtection(hProcess: ctypes.wintypes.HANDLE, pid: int, protAddr: int) -> bool:
        te32 = ctypes.Structure()
        te32.dwSize = ctypes.sizeof(te32)
        hThreadSnap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        if hThreadSnap == -1:
            return False

        if not ctypes.windll.kernel32.Thread32First(hThreadSnap, ctypes.byref(te32)):
            ctypes.windll.kernel32.CloseHandle(hThreadSnap)
            return False

        while True:
            if te32.th32OwnerProcessID == pid:
                threadInfo = ctypes.c_void_p()
                retLen = ctypes.c_ulong()
                NtQueryInformationThread = ctypes.windll.ntdll.NtQueryInformationThread
                hThread = ctypes.windll.kernel32.OpenThread(0x1F03FF, 0, te32.th32ThreadID)
                if not hThread:
                    ctypes.windll.kernel32.CloseHandle(hThreadSnap)
                    return False

                ntqiRet = NtQueryInformationThread(hThread, 9, ctypes.byref(threadInfo), ctypes.sizeof(threadInfo), ctypes.byref(retLen))
                if ntqiRet != 0:
                    ctypes.windll.kernel32.CloseHandle(hThreadSnap)
                    ctypes.windll.kernel32.CloseHandle(hThread)
                    return False

                mbi = ctypes.Structure()
                if ctypes.windll.kernel32.VirtualQueryEx(hProcess, threadInfo, ctypes.byref(mbi), ctypes.sizeof(mbi)):
                    baseAddress = mbi.AllocationBase
                    if baseAddress == protAddr:
                        ctypes.windll.kernel32.SuspendThread(hThread)
                        ctypes.windll.kernel32.CloseHandle(hThreadSnap)
                        ctypes.windll.kernel32.CloseHandle(hThread)
                        return True

                ctypes.windll.kernel32.CloseHandle(hThread)

            if not ctypes.windll.kernel32.Thread32Next(hThreadSnap, ctypes.byref(te32)):
                break

        ctypes.windll.kernel32.CloseHandle(hThreadSnap)
        return False

    @staticmethod
    def Patch(address: int, data: bytes, size: int, handle: ctypes.wintypes.HANDLE) -> bool:
        oldProtect = ctypes.c_ulong()
        if not ctypes.windll.kernel32.VirtualProtectEx(handle, address, size, 0x40, ctypes.byref(oldProtect)):
            return False

        if not ctypes.windll.kernel32.WriteProcessMemory(handle, address, data, size, None):
            return False

        if not ctypes.windll.kernel32.VirtualProtectEx(handle, address, size, oldProtect, ctypes.byref(oldProtect)):
            return False

        return True

    @staticmethod
    def GetLibraryProcAddress(library: str, function: str) -> Optional[int]:
        hModule = ctypes.windll.kernel32.GetModuleHandleA(library.encode())
        if not hModule:
            return None

        return ctypes.windll.kernel32.GetProcAddress(hModule, function.encode())

    @staticmethod
    def GetModuleAddress(module: str, pid: int) -> Optional[int]:
        hSnapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x00000008, pid)
        if hSnapshot == -1:
            return None

        me32 = ctypes.Structure()
        me32.dwSize = ctypes.sizeof(me32)
        if not ctypes.windll.kernel32.Module32First(hSnapshot, ctypes.byref(me32)):
            ctypes.windll.kernel32.CloseHandle(hSnapshot)
            return None

        while True:
            if me32.szModule.decode().lower() == module.lower():
                ctypes.windll.kernel32.CloseHandle(hSnapshot)
                return me32.modBaseAddr

            if not ctypes.windll.kernel32.Module32Next(hSnapshot, ctypes.byref(me32)):
                break

        ctypes.windll.kernel32.CloseHandle(hSnapshot)
        return None

    @staticmethod
    def Inject(handle: ctypes.wintypes.HANDLE, dllPath: str) -> bool:
        if not os.path.isfile(dllPath):
            return False

        is_64bit = sys.maxsize > 2**32
        if is_64bit:
            process_arch = "x64"
        else:
            process_arch = "x86"

        dll_arch = get_dll_architecture(dllPath)
        if process_arch != dll_arch:
            return False

        with open(dllPath, "rb") as f:
            dll_bytes = f.read()

        encoded_dll_bytes = vmprotect.vmp_encode(dll_bytes)

        size_of_image = len(encoded_dll_bytes)
        remote_address = ctypes.windll.kernel32.VirtualAllocEx(handle, None, size_of_image, 0x3000, 0x40)
        if not remote_address:
            return False

        if not ctypes.windll.kernel32.WriteProcessMemory(handle, remote_address, encoded_dll_bytes, size_of_image, None):
            return False

        thread_id = ctypes.c_ulong(0)
        if not ctypes.windll.kernel32.CreateRemoteThread(handle, None, 0, remote_address, None, 0, ctypes.byref(thread_id)):
            return False

        if ctypes.windll.kernel32.WaitForSingleObject(thread_id, -1) == 0xFFFFFFFF:
            return False

        if not ctypes.windll.kernel32.VirtualFreeEx(handle, remote_address, 0, 0x8000):
            return False

        return True

    @staticmethod
    def Bedge(ms: int) -> None:
        time.sleep(ms / 1000.0)

    @staticmethod
    def Attack(dll_path, process_name, process_window_name):
        isInjected = False
        while True:
            hwnd = None
            while hwnd is None:
                hwnd = ctypes.windll.user32.FindWindowW(process_window_name.encode("utf-16le"), None)
                if hwnd == 0:
                    isInjected = False
                    Injector.Bedge(1000)

            dwProcID = wintypes.DWORD()
            while not ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(dwProcID)) or dwProcID.value == 0:
                Injector.Bedge(1000)

            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, dwProcID.value)

            # Restore bytes of these hooked function
            Injector.Patch(Injector.GetLibraryProcAddress(b"ntdll.dll", b"LdrInitializeThunk"), b"\x40\x53\x48\x83\xEC\x20", 6, handle)
            Injector.Patch(Injector.GetLibraryProcAddress(b"ntdll.dll", b"NtQueryAttributesFile"), b"\x4C\x8B\xD1\xB8\x3D\x00\x00\x00", 8, handle)

            split_result = process_name.split(".")
            process_name_joined = ".".join(split_result[:-1])
          
            process_dll_main_addr = Injector.GetModuleAddress(f"{process_name_joined}.dll", dwProcID.value)
            if process_dll_main_addr == 0:
              print(f"{process_name_joined}.dll not found!")
              return isInjected

            if SuspendProtection(handle, dwProcID.value, process_dll_main_addr):
              if not isInjected:
                isInjected = Inject(handle, dll_path)
            Bedge(20)
            ctypes.windll.kernel32.TerminateProcess(ctypes.wintypes.HANDLE(-1), 0)
            return isInjected
