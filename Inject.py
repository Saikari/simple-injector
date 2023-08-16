from subprocess import Popen
from ctypes import (
    WinError, byref, c_int, c_long, c_ulong,
    create_string_buffer, windll
)


class Injector:
    PROC_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)
    MEM_CREATE = 0x00001000 | 0x00002000
    MEM_RELEASE = 0x8000
    PAGE_EXECUTE_READWRITE = 0x40

    def __init__(self):
        self.kernel32 = windll.kernel32
        self.pid = c_ulong()
        self.handle = None

    def create_process(self, path: str) -> int:
        """Create a new process and return its PID."""
        return Popen([path]).pid

    def load_from_pid(self, pid: int) -> None:
        """Load a handle to an existing process."""
        self.unload()
        self.pid = c_ulong(pid)
        self.handle = self.kernel32.OpenProcess(self.PROC_ALL_ACCESS, 0, pid)
        if not self.handle:
            raise WinError('Unable to load from pid.')

    def unload(self) -> None:
        """Close the handle to the current process."""
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
            if not self.handle:
                raise WinError('Unable to unload.')
        self.handle = None

    def alloc_remote(self, buffer: bytes, size: int) -> int:
        """Allocate memory in the remote process and return the address."""
        alloc = self.kernel32.VirtualAllocEx(
            self.handle, None, c_int(size),
            self.MEM_CREATE, self.PAGE_EXECUTE_READWRITE
        )
        if not alloc:
            raise WinError('Unable to allocate remote memory.')
        self.write_memory(alloc, buffer)
        return alloc

    def free_remote(self, addr: int, size: int) -> None:
        """Free memory in the remote process."""
        if not self.kernel32.VirtualFreeEx(self.handle, addr, c_int(0), self.MEM_RELEASE):
            raise WinError('Unable to free remote memory.')

    def get_address_from_module(self, module: str, function: str) -> int:
        """Get the address of an exported function from a module."""
        module_addr = self.kernel32.GetModuleHandleA(module.encode("ascii"))
        if not module_addr:
            raise WinError('Unable to get module address.')
        function_addr = self.kernel32.GetProcAddress(module_addr, function.encode("ascii"))
        if not function_addr:
            raise WinError('Unable to get function address.')
        return function_addr

    def create_remote_thread(self, function_addr: int, args: bytes) -> int:
        """Create a remote thread in the remote process."""
        dll_addr = c_long(0)
        args_addr = self.alloc_remote(args, len(args))
        thread = self.kernel32.CreateRemoteThread(
            self.handle, None, None, c_long(function_addr),
            c_long(args_addr), None, None
        )
        if not thread:
            raise WinError('Unable to create remote thread.')
        if self.kernel32.WaitForSingleObject(thread, 0xFFFFFFFF) == 0xFFFFFFFF:
            raise WinError('Remote thread execution failed.')
        if not self.kernel32.GetExitCodeThread(thread, byref(dll_addr)):
            raise WinError('Unable to get exit code of remote thread.')
        self.free_remote(args_addr, len(args))
        return dll_addr.value

    def read_memory(self, addr: int, size: int) -> bytes:
        """Read memory from the remote process."""
        old_protect = c_ulong()
        if not self.kernel32.VirtualProtectEx(self.handle, addr, size, self.PAGE_EXECUTE_READWRITE, byref(old_protect)):
            raise WinError('Unable to change memory protection.')
        buffer = create_string_buffer(size)
        if not self.kernel32.ReadProcessMemory(self.handle, c_long(addr), buffer, size, None):
            raise WinError('Unable to read memory.')
        if not self.kernel32.VirtualProtectEx(self.handle, addr, size, old_protect, byref(old_protect)):
            raise WinError('Unable to change memory protection.')
        return buffer

    def write_memory(self, addr: int, string: bytes) -> None:
        """Write memory to the remote process."""
        size = len(string)
        old_protect = c_ulong()
        if not self.kernel32.VirtualProtectEx(self.handle, addr, size, self.PAGE_EXECUTE_READWRITE, byref(old_protect)):
            raise WinError('Unable to change memory protection.')
        if not self.kernel32.WriteProcessMemory(self.handle, addr, string, size, None):
            raise WinError('Unable to write memory.')
        if not self.kernel32.VirtualProtectEx(self.handle, addr, size, old_protect, byref(old_protect)):
            raise WinError('Unable to change memory protection.')

    def load_library(self, buffer: bytes) -> int:
        """Load a library into the remote process."""
        function_addr = self.get_address_from_module("kernel32.dll", "LoadLibraryW")
        dll_addr = self.create_remote_thread(function_addr, buffer)
        return dll_addr

    def inject_dll(self, path: str) -> int:
        """Inject a DLL into the remote process."""
        self.path = path
        return self.load_library(path.encode("utf-16le"))

    def call_from_injected(self, path: str, dll_addr: int, function: str, args: bytes) -> None:
        """Call a function from the injected DLL."""
        function_offset = self.get_offset_of_exported_function(path.encode("utf-16le"), function)
        self.create_remote_thread(dll_addr + function_offset, args)
    
    def get_offset_of_exported_function(self, module: str, function: str) -> int:
        """Get the offset of an exported function from a module."""
        base_addr = self.kernel32.LoadLibraryW(module)
        if not base_addr:
            raise WinError('Unable to load library.')
        function_addr = self.kernel32.GetProcAddress(base_addr, function.encode("utf-16le"))
        if not function_addr:
            raise WinError('Unable to get function address.')
        if not self.kernel32.FreeLibrary(base_addr):
            raise WinError('Unable to free library.')
        return function_addr - base_addr

