use core::{ffi::c_void, mem, ptr};

use alloc::string::String;
use print_no_std::println;
use windows::Win32::{Foundation::NTSTATUS, System::{
    Diagnostics::Debug::{
        IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
    },
    SystemServices::{
        IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
        IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64,
    },
    Threading::GetCurrentProcess,
}};

use crate::ntapi::NtWriteVirtualMemory;

pub fn write_sections(
    buffer: &[u8],
    baseptr: *mut c_void,
    nt_header: &IMAGE_NT_HEADERS64,
    dos_header: &IMAGE_DOS_HEADER,
) {
    let e_lfanew = dos_header.e_lfanew as usize;
    let section_count = nt_header.FileHeader.NumberOfSections as usize;
    let section_header = unsafe {
        buffer
            .as_ptr()
            .add(e_lfanew + mem::size_of::<IMAGE_NT_HEADERS64>())
            .cast::<IMAGE_SECTION_HEADER>()
    };

    for _i in 0..section_count {
        let section = unsafe { ptr::read_unaligned(section_header.add(_i)) };
        let section_name_str = String::from_utf8_lossy(section.Name.as_slice());
        println!("Section name: {}", section_name_str);

        let section_virtual_address = section.VirtualAddress as usize;
        let section_size = section.SizeOfRawData as usize;

        let src = unsafe { buffer.as_ptr().add(section.PointerToRawData as usize) };

        unsafe {
            let status = NtWriteVirtualMemory(
                GetCurrentProcess(),
                baseptr.add(section_virtual_address as usize),
                src as *const c_void,
                section_size,
                ptr::null_mut(),
            );
            if status != NTSTATUS(0) {
                panic!("Failed to write section {}: {}", section_name_str, status.0);
            }
        };
    }
}

pub fn fix_relocations(baseptr: *mut c_void, nt_header: &IMAGE_NT_HEADERS64) {
    let preferred_image_base = nt_header.OptionalHeader.ImageBase;
    let actual_image_base = baseptr as u64;
    let delta = actual_image_base.wrapping_sub(preferred_image_base);

    if delta == 0 {
        println!("No relocations needed");
        return;
    }

    let reloc_dir_entry =
        nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize];

    if reloc_dir_entry.VirtualAddress == 0 || reloc_dir_entry.Size == 0 {
        panic!(
            "No relocation directory found (PE is non-relocatable), but delta is {} bytes",
            delta
        );
    }

    let mut current_reloc_block_ptr = unsafe {
        baseptr
            .add(reloc_dir_entry.VirtualAddress as usize)
            .cast::<IMAGE_BASE_RELOCATION>()
    };
    let reloc_dir_end_ptr =
        unsafe { (current_reloc_block_ptr as *const u8).add(reloc_dir_entry.Size as usize) };

    while unsafe {
        (*current_reloc_block_ptr).VirtualAddress != 0
            && (*current_reloc_block_ptr).SizeOfBlock != 0
    } && (current_reloc_block_ptr as *const u8) < reloc_dir_end_ptr
    {
        let reloc_block = unsafe { *current_reloc_block_ptr };
        let block_base_rva = reloc_block.VirtualAddress;
        let block_size = reloc_block.SizeOfBlock;

        let num_entries = (block_size as usize - mem::size_of::<IMAGE_BASE_RELOCATION>())
            / mem::size_of::<u16>();
        let entry_ptr = unsafe {
            (current_reloc_block_ptr as *const u8)
                .add(mem::size_of::<IMAGE_BASE_RELOCATION>())
                .cast::<u16>()
        };
        for _i in 0..num_entries {
            let entry = unsafe { *entry_ptr.add(_i) };
            let reloc_type = (entry >> 12) as u32;
            let reloc_offset = entry & 0x0FFF;

            let fixup_rva = block_base_rva + reloc_offset as u32;
            let fixup_ptr = unsafe { baseptr.add(fixup_rva as usize) };

            match reloc_type {
                IMAGE_REL_BASED_ABSOLUTE => {}
                IMAGE_REL_BASED_DIR64 => {
                    let fixup_value = unsafe { *(fixup_ptr as *const u64) };
                    let new_value = fixup_value.wrapping_add(delta);
                    unsafe {
                        *(fixup_ptr as *mut u64) = new_value;
                    }
                }
                _ => {
                    panic!("Unsupported relocation type: {}", reloc_type);
                }
            }
        }

        current_reloc_block_ptr = unsafe {
            (current_reloc_block_ptr as *mut u8)
                .add(block_size as usize)
                .cast::<IMAGE_BASE_RELOCATION>()
        };
    }
}

pub fn get_dos_header(buffer: &[u8]) -> IMAGE_DOS_HEADER {
    let dos_header = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<IMAGE_DOS_HEADER>()) };
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        panic!("Invalid DOS signature");
    };
    dos_header
}

pub fn get_nt_header(buffer: &[u8]) -> IMAGE_NT_HEADERS64 {
    let dos_header = get_dos_header(buffer);
    let nt_header = unsafe {
        ptr::read_unaligned(
            buffer
                .as_ptr()
                .add(dos_header.e_lfanew as usize)
                .cast::<IMAGE_NT_HEADERS64>(),
        )
    };
    if nt_header.Signature != IMAGE_NT_SIGNATURE {
        panic!("Invalid NT signature");
    };
    nt_header
}

pub fn get_image_size(buffer: &[u8]) -> usize {
    let nt_header = get_nt_header(buffer);
    let size_of_image = nt_header.OptionalHeader.SizeOfImage as usize;
    size_of_image
}
