from ctypes import byref, windll, sizeof, Structure, c_void_p, c_ulong
from ctypes import wintypes
from time import sleep
from typing import Optional
from Injector import Injector


class Bypass:
    PROCESS_ALL_ACCESS = 0x1F0FFF
    @staticmethod
    def SuspendProtection(hProcess: wintypes.HANDLE, pid: int, protAddr: int) -> bool:
        te32 = Structure()
        te32.dwSize = sizeof(te32)
        hThreadSnap = windll.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        if hThreadSnap == -1:
            return False

        if not windll.kernel32.Thread32First(hThreadSnap, byref(te32)):
            windll.kernel32.CloseHandle(hThreadSnap)
            return False

        while True:
            if te32.th32OwnerProcessID == pid:
                threadInfo = c_void_p()
                retLen = c_ulong()
                NtQueryInformationThread = windll.ntdll.NtQueryInformationThread
                hThread = windll.kernel32.OpenThread(0x1F03FF, 0, te32.th32ThreadID)
                if not hThread:
                    windll.kernel32.CloseHandle(hThreadSnap)
                    return False

                ntqiRet = NtQueryInformationThread(hThread, 9, byref(threadInfo), sizeof(threadInfo), byref(retLen))
                if ntqiRet != 0:
                    windll.kernel32.CloseHandle(hThreadSnap)
                    windll.kernel32.CloseHandle(hThread)
                    return False

                mbi = Structure()
                if windll.kernel32.VirtualQueryEx(hProcess, threadInfo, byref(mbi), sizeof(mbi)):
                    baseAddress = mbi.AllocationBase
                    if baseAddress == protAddr:
                        windll.kernel32.SuspendThread(hThread)
                        windll.kernel32.CloseHandle(hThreadSnap)
                        windll.kernel32.CloseHandle(hThread)
                        return True

                windll.kernel32.CloseHandle(hThread)

            if not windll.kernel32.Thread32Next(hThreadSnap, byref(te32)):
                break

        windll.kernel32.CloseHandle(hThreadSnap)
        return False

    @staticmethod
    def Patch(address: int, data: bytes, size: int, handle: wintypes.HANDLE) -> bool:
        oldProtect = c_ulong()
        if not windll.kernel32.VirtualProtectEx(handle, address, size, 0x40, byref(oldProtect)):
            return False

        if not windll.kernel32.WriteProcessMemory(handle, address, data, size, None):
            return False

        if not windll.kernel32.VirtualProtectEx(handle, address, size, oldProtect, byref(oldProtect)):
            return False

        return True

    @staticmethod
    def GetLibraryProcAddress(library: str, function: str) -> Optional[int]:
        hModule = windll.kernel32.GetModuleHandleA(library.encode())
        if not hModule:
            return None

        return windll.kernel32.GetProcAddress(hModule, function.encode())

    @staticmethod
    def GetModuleAddress(module: str, pid: int) -> Optional[int]:
        hSnapshot = windll.kernel32.CreateToolhelp32Snapshot(0x00000008, pid)
        if hSnapshot == -1:
            return None

        me32 = Structure()
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
    def Attack(dll_path, process_name, process_window_name) -> bool:
        syringe = Injector()
        isInjected = False
        hwnd = None
        while not isInjected:
            while hwnd is None:
                hwnd = windll.user32.FindWindowW(process_window_name.encode("utf-16le"), None)
                if hwnd == 0:
                    isInjected = False
                    Bypass.Bedge(1000)

            dwThreadId = windll.user32.GetWindowThreadProcessId(hwnd, None)
            dwProcID = wintypes.DWORD(dwThreadId)
            while not windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, dwProcID.value):
                Bypass.Bedge(1000)

            handle = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, dwProcID.value)

            # Restore bytes of these hooked function
            Bypass.Patch(Bypass.GetLibraryProcAddress("ntdll.dll", "LdrInitializeThunk"),
                         b"\x40\x53\x48\x83\xEC\x20", 6, handle)
            Bypass.Patch(Bypass.GetLibraryProcAddress("ntdll.dll", "NtQueryAttributesFile"),
                         b"\x4C\x8B\xD1\xB8\x3D\x00\x00\x00", 8, handle)

            split_result = process_name.split(".")
            process_name_joined = ".".join(split_result[:-1])

            process_dll_main_addr = Bypass.GetModuleAddress(f"{process_name_joined}.dll", dwProcID.value)
            if process_dll_main_addr == 0:
                print(f"{process_name_joined}.dll not found!")
                return isInjected

            if Bypass.SuspendProtection(handle, dwProcID.value, process_dll_main_addr):
                if not isInjected:
                    isInjected = syringe.inject_dll(handle, dll_path, hwnd)
            Bypass.Bedge(20)
        windll.kernel32.TerminateProcess(wintypes.HANDLE(-1), 0)
        return isInjected
