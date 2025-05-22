use core::ffi::{self, c_void};

use alloc::string::String;
use print_no_std::println;
use windows::{
    Win32::{
        Foundation::FARPROC,
        System::{
            Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_NT_HEADERS64},
            LibraryLoader::{GetProcAddress, LoadLibraryA},
            SystemServices::{IMAGE_IMPORT_DESCRIPTOR, IMAGE_ORDINAL_FLAG64},
            WindowsProgramming::IMAGE_THUNK_DATA64,
        },
    },
    core::PCSTR,
};

pub fn resolve_imports(
    baseptr: *mut c_void,
    nt_header: &IMAGE_NT_HEADERS64,
) {
    unsafe {
        let import_dir_rva = nt_header.OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize]
            .VirtualAddress;
        if import_dir_rva == 0 {
            println!("No import directory found");
            return;
        }

        let mut import_descriptor_ptr = baseptr
            .add(import_dir_rva as usize)
            .cast::<IMAGE_IMPORT_DESCRIPTOR>();

        while (*import_descriptor_ptr).Name != 0 {
            let import_descriptor = &*import_descriptor_ptr;
            let dll_name_rva = import_descriptor.Name;
            let dll_name_c_ptr = baseptr.add(dll_name_rva as usize) as *const u8;
            let dll_name_str = get_string_from_rva(baseptr, dll_name_rva);
            let dll_handle = LoadLibraryA(PCSTR(dll_name_c_ptr))
                .unwrap_or_else(|e| panic!("Failed to load DLL {}: {}", dll_name_str, e));
            println!("Found DLL: {}", dll_name_str);

            let mut thunk_rva = import_descriptor.Anonymous.OriginalFirstThunk;
            if thunk_rva == 0 {
                thunk_rva = import_descriptor.FirstThunk;
            }
            let mut thunk_ptr = baseptr.add(thunk_rva as usize).cast::<IMAGE_THUNK_DATA64>();
            let mut iat_write_ptr = baseptr.add(import_descriptor.FirstThunk as usize).cast::<FARPROC>();

            while thunk_ptr.read().u1.AddressOfData != 0 {
                let thunk_data = *thunk_ptr;
                let mut resolved_proc_address: FARPROC = FARPROC::default();

                if (thunk_data.u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0 {
                    let ordinal = (thunk_data.u1.Ordinal & !IMAGE_ORDINAL_FLAG64) as u16;
                    resolved_proc_address = GetProcAddress(dll_handle, PCSTR(ordinal as usize as *const u8));
                } else {
                    let import_by_name_rva = thunk_data.u1.AddressOfData as u32;
                    let import_by_name_ptr =
                        baseptr
                            .add(import_by_name_rva as usize)
                            .cast::<windows::Win32::System::SystemServices::IMAGE_IMPORT_BY_NAME>();

                    let func_name_ptr = (*import_by_name_ptr).Name.as_ptr();
                    resolved_proc_address = GetProcAddress(dll_handle, PCSTR(func_name_ptr as *const u8));
                }

                if resolved_proc_address.is_some() {
                    *iat_write_ptr = resolved_proc_address;
                     println!("      IAT @ {:?} updated with {:?}", iat_write_ptr, resolved_proc_address.unwrap());
                } else {
                    panic!("Failed to resolve function address");
                }

                thunk_ptr = thunk_ptr.add(1);
                iat_write_ptr = iat_write_ptr.add(1);
            }

            import_descriptor_ptr = import_descriptor_ptr.add(1);
        }
    }
}

unsafe fn get_string_from_rva(baseptr: *mut c_void, rva: u32) -> String {
    let str_ptr = unsafe { baseptr.add(rva as usize) } as *const i8;
    let cstr = unsafe { ffi::CStr::from_ptr(str_ptr) };
    cstr.to_string_lossy().into_owned()
}
