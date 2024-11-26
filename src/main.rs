//use noldr::{get_dll_address, get_teb};
use winapi::um::processthreadsapi::CreateProcessA;
use winapi::um::winbase::{NORMAL_PRIORITY_CLASS, DETACHED_PROCESS, DEBUG_PROCESS};
use winapi::um::processthreadsapi::STARTUPINFOA;
use winapi::um::processthreadsapi::PROCESS_INFORMATION;

mod func;

fn main() {
    //let teb = get_teb();
    //println!("teb: {:?}", teb);

    //need to add error handling
    //let ntdll = get_dll_address("ntdll.dll".to_string(), teb).unwrap();

    //set the process name to cmd.exe for testing
    let process_name = "cmd.exe".to_string();

    let process_path = if !process_name.contains('\\') {
        format!("C:\\Windows\\System32\\{}", process_name)
    } else {
        process_name
    };

    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

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
            &mut pi
        )
    };

    if success == 0 {
        eprintln!("Failed to create process: {}", unsafe { winapi::um::errhandlingapi::GetLastError() });
        std::process::exit(1);
    }

    println!("Process created successfully");
    println!("Process Handle: 0x{:x}", pi.hProcess as usize);
    println!("Thread Handle: 0x{:x}", pi.hThread as usize);
    println!("Process ID: {}", pi.dwProcessId);
    println!("Thread ID: {}", pi.dwThreadId);

    //take a snapshot of the process
    match func::capture_process_snapshot(pi.hProcess) {
        Ok(_) => println!("Main function ending - snapshot should be freed here"),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }



}
