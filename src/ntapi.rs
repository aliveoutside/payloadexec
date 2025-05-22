use core::ffi::c_void;

use windows::Win32::Foundation::{HANDLE, NTSTATUS};

#[link(name = "ntdll")]
unsafe extern "system" {
    pub fn NtWriteVirtualMemory(
        hProcess: HANDLE,
        lpBaseAddress: *mut c_void,
        lpBuffer: *const c_void,
        nSize: usize,
        lpNumberOfBytesWritten: *mut usize,
    ) -> NTSTATUS;
}