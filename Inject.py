import ctypes
import subprocess
import mmap
#import vmprotect
import os
import sys
from . import CertificateGenerator
import struct

def get_dll_architecture(dll_path):
    with open(dll_path, 'rb') as f:
        dos_header = f.read(64)
        magic, _, _, _, _, _ = struct.unpack('2s58s', dos_header)
        if magic != b'MZ':
            raise ValueError('Invalid DOS header')
        pe_header_offset, = struct.unpack('I', dos_header[60:64])
        f.seek(pe_header_offset)
        pe_header = f.read(6)
        magic, machine = struct.unpack('2sH', pe_header)
        if magic != b'PE' or machine not in (0x014c, 0x8664):
            raise ValueError('Invalid PE header')
        return '32-bit' if machine == 0x014c else '64-bit'

class Injector:
    PROC_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)
    MEM_CREATE = 0x00001000 | 0x00002000
    MEM_RELEASE = 0x8000
    PAGE_EXECUTE_READWRITE = 0x40
    PROCESS_ALL_ACCESS = 0x1F0FFF
    THREAD_ALL_ACCESS = 0x1F03FF
    ThreadQuerySetWin32StartAddress = 9

    
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.pid = ctypes.c_ulong()
        self.handle = None

    def create_process(self, path: str) -> int:
        """Create a new process and return its PID."""
        return subprocess.Popen([path]).pid

    def load_from_pid(self, pid: int) -> None:
        """Load a handle to an existing process."""
        self.unload()
        self.pid = ctypes.c_ulong(pid)
        self.handle = self.kernel32.OpenProcess(self.PROC_ALL_ACCESS, 0, pid)
        if not self.handle:
            raise ctypes.WinError()

    def unload(self) -> None:
        """Close the handle to the current process."""
        if self.handle:
            if not self.kernel32.CloseHandle(self.handle):
                raise ctypes.WinError()
        self.handle = None

    def alloc_remote(self, buffer: bytes, size: int) -> ctypes.LPVOID:
        """Allocate memory in the remote process and return the address."""
        alloc = self.kernel32.VirtualAllocEx(
            self.handle, None, ctypes.c_int(size),
            self.MEM_CREATE, self.PAGE_EXECUTE_READWRITE
        )
        if not alloc:
            raise ctypes.WinError()
        self.write_memory(alloc, buffer)
        return alloc

    def free_remote(self, addr: ctypes.LPVOID, size: int) -> None:
        """Free memory in the remote process."""
        if not self.kernel32.VirtualFreeEx(self.handle, addr, ctypes.c_int(0), self.MEM_RELEASE):
            raise ctypes.WinError()

    def get_address_from_module(self, module: str, function: str) -> ctypes.LPVOID:
        """Get the address of an exported function from a module."""
        module_addr = self.kernel32.GetModuleHandleW(module.encode("utf-16le"))
        if not module_addr:
            raise ctypes.WinError()
        function_addr = self.kernel32.GetProcAddress(module_addr, function.encode("utf-16le"))
        if not function_addr:
            raise ctypes.WinError()
        return function_addr

    def create_remote_thread(self, function_addr: ctypes.LPVOID, args: bytes) -> ctypes.LPVOID:
        """Create a remote thread in the remote process."""
        dll_addr = ctypes.c_long(0)
        args_addr = self.alloc_remote(args, len(args))
        thread = self.kernel32.CreateRemoteThread(
            self.handle, None, None, function_addr,
            args_addr, None, None
        )
        if not thread:
            raise ctypes.WinError()
        if self.kernel32.WaitForSingleObject(thread, 0xFFFFFFFF) == 0xFFFFFFFF:
            raise ctypes.WinError()
        if not self.kernel32.GetExitCodeThread(thread, ctypes.byref(dll_addr)):
            raise ctypes.WinError()
        self.free_remote(args_addr, len(args))
        return dll_addr.value

    def read_memory(self, addr: ctypes.LPVOID, size: int) -> bytes:
        """Read memory from the remote process."""
        old_protect = ctypes.c_ulong()
        if not self.kernel32.VirtualProtectEx(self.handle, addr, size, self.PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect)):
            raise ctypes.WinError()
        buffer = ctypes.create_string_buffer(size)
        if not self.kernel32.ReadProcessMemory(self.handle, ctypes.c_long(addr), buffer, size, None):
            raise ctypes.WinError()
        if not self.kernel32.VirtualProtectEx(self.handle, addr, size, old_protect, ctypes.byref(old_protect)):
            raise ctypes.WinError()
        return buffer.raw

    def write_memory(self, addr: ctypes.LPVOID, string: bytes) -> None:
        """Write memory to the remote process."""
        size = len(string)
        old_protect = ctypes.c_ulong()
        if not self.kernel32.VirtualProtectEx(self.handle, addr, size, self.PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect)):
            raise ctypes.WinError()
        if not self.kernel32.WriteProcessMemory(self.handle, addr, string, size, None):
            raise ctypes.WinError()
        if not self.kernel32.VirtualProtectEx(self.handle, addr, size, old_protect, ctypes.byref(old_protect)):
            raise ctypes.WinError()

    def inject_dll(self, path: str, process_handle: int) -> ctypes.LPVOID:
        """Inject a DLL into the remote process."""
        # Check if the DLL file exists
        if not os.path.isfile(path):
            raise FileNotFoundError(f"DLL file '{path}' does not exist.")
             
        # Check the process architecture
        is_64bit = sys.maxsize > 2**32
        if is_64bit:
            process_arch = "x64"
        else:
            process_arch = "x86"
        

        # Sign the DLL using the CertificateGenerator class
        cert_generator = CertificateGenerator(outFile="certificate.pem", inputFile="private_key.pem", domain="example.com", password="password", real=True, verify=True)
        cert_generator.GenerateCert("example.com", "inputFile.pem")
        signed_dll_path = cert_generator.certToFile("signed_dll.dll", path)


        # Check the DLL architecture
        dll_arch = get_dll_architecture(signed_dll_path)
        if process_arch != dll_arch:
            raise ValueError(f"The process architecture ({process_arch}) does not match the DLL architecture ({dll_arch}).")
        
        
        # Read the DLL file into memory
        with open(signed_dll_path, "rb") as f:
            dll_bytes = f.read()
    
        # Encode the DLL using VMProtect
        #encoded_dll_bytes = vmprotect.vmp_encode(dll_bytes)
    
        # Allocate memory in the remote process
        size_of_image = len(encoded_dll_bytes)
        remote_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, 0, size_of_image, 0x3000, 0x40)
        if not remote_address:
            raise ctypes.WinError()
    
        # Write the encoded DLL bytes to the allocated memory
        ctypes.windll.kernel32.WriteProcessMemory(process_handle, remote_address, encoded_dll_bytes, size_of_image, 0)
    
        # Execute the DLL in the remote process
        thread_id = ctypes.c_ulong(0)
        ctypes.windll.kernel32.CreateRemoteThread(process_handle, None, 0, remote_address, None, 0, ctypes.byref(thread_id))
    
        # Wait for the remote thread to finish
        ctypes.windll.kernel32.WaitForSingleObject(thread_id, -1)
    
        # Free the allocated memory
        ctypes.windll.kernel32.VirtualFreeEx(process_handle, remote_address, 0, 0x8000)
    
        # Get the address of the loaded DLL
        module_handle = ctypes.windll.kernel32.GetModuleHandleW(signed_dll_path.encode("utf-16le"))
        if not module_handle:
            raise ctypes.WinError()

        return module_handle


    def call_from_injected(self, path: str, dll_addr: ctypes.LPVOID, function: str, args: bytes) -> None:
        """Call a function from the injected DLL."""
        function_offset = self.get_offset_of_exported_function(path.encode("utf-16le"), function)
        self.create_remote_thread(dll_addr + function_offset, args)

    def get_offset_of_exported_function(self, module: str, function: str) -> int:
        """Get the offset of an exported function from a module."""
        base_addr = self.kernel32.LoadLibraryW(module.encode("utf-16le"))
        if not base_addr:
            raise ctypes.WinError()
        function_addr = self.kernel32.GetProcAddress(base_addr, function.encode("utf-16le"))
        if not function_addr:
            raise ctypes.WinError()
        if not self.kernel32.FreeLibrary(base_addr):
            raise ctypes.WinError()
        return function_addr - base_addr
