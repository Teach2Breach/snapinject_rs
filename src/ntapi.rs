///dynamically resolving Nt* functions to make snapinject have opsec
/// RustVEHSyscalls used for initialize_hooks() and destroy_hooks()
/// 
/// The effect of calling the above two functions in dynamic resolving with dinvoke_rs::dinvoke::dynamic_invoke!()
/// has not been tested yet. Please test it and let me know if it works.
/// 
/// Using unwinder for indirect syscalls with call stack spoofing is not implemented for all syscalls yet
/// and also not tested. Please test it and let me know if it works.


//indirect dynamic syscalls using VEH and Unwinder callstack spoofing

#![allow(non_snake_case, unused_imports)]
use winapi::shared::windef::SIZE;
use std::env::consts;
use std::ffi::{OsStr, c_char, CStr, c_int};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::{mem::size_of, ptr::null_mut};
use widestring::U16CString;
use winapi::ctypes::c_void;
use std::mem;


/*use windows_sys::Win32::{
   System::{
        Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ},
        SystemServices::{IMAGE_DOS_HEADER},
        Threading::{ PROCESS_ALL_ACCESS},
    }, 
    
    
};  */

use winapi::{
    vc::excpt::{EXCEPTION_CONTINUE_EXECUTION,EXCEPTION_CONTINUE_SEARCH},
    shared::{
        ntdef::{HANDLE, PVOID, OBJECT_ATTRIBUTES, NT_SUCCESS, NTSTATUS, UNICODE_STRING, LIST_ENTRY, SHORT, WCHAR,LONG},
        basetsd::SIZE_T,
        minwindef::{ULONG,DWORD},
        ntstatus::STATUS_SUCCESS,
    },

    um::{
        winnt::{
                THREAD_ALL_ACCESS, CONTEXT, CONTEXT_ALL, IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER, IMAGE_DOS_HEADER,
                IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_EXPORT_DIRECTORY,IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_SIGNATURE, 
                IMAGE_DOS_SIGNATURE, LARGE_INTEGER, MEM_RELEASE, PAGE_EXECUTE_READWRITE, MEMORY_BASIC_INFORMATION, EXCEPTION_POINTERS,
                THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, PROCESS_ALL_ACCESS,
            },
        errhandlingapi::AddVectoredExceptionHandler,
        minwinbase::EXCEPTION_SINGLE_STEP,
    },
};

use ntapi::{
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntpsapi::{PEB_LDR_DATA, PROCESS_BASIC_INFORMATION, ProcessBasicInformation, PS_ATTRIBUTE, PS_ATTRIBUTE_LIST, PS_CREATE_INFO, ProcessImageFileName},
    ntpebteb::PEB,
    ntexapi::{SYSTEM_PROCESS_INFORMATION, SystemProcessInformation, SYSTEM_THREAD_INFORMATION, SYSTEM_INFORMATION_CLASS},
    ntrtl::{RtlCreateProcessParametersEx ,RtlDestroyProcessParameters},
    ntobapi::DUPLICATE_SAME_ACCESS,
    ntmmapi::MEMORY_INFORMATION_CLASS,
};
use dinvoke_rs::dinvoke;
use unwinder;
use rust_veh_syscalls::hooks::{initialize_hooks, destroy_hooks};



use muddy::{m, muddy_init};

muddy_init!("env");


#[repr(C)]
pub struct CLIENT_ID {
    pub UniqueProcess: HANDLE,
    pub UniqueThread: HANDLE,

}

//dynamic NT functions
//function pointers
type NtClose = unsafe extern "system" fn(HANDLE) -> i32;
type NtDuplicateObject = unsafe extern "system" fn(
    source_process_handle: HANDLE,
    source_handle: HANDLE,
    target_process_handle: HANDLE,
    target_handle: *mut HANDLE,
    desired_access: u32,
    handleattributes: u32,
    options: u32,
) -> NTSTATUS;
type NtQuerySystemInformation = unsafe extern "system" fn(
    systeminformationclass: SYSTEM_INFORMATION_CLASS,
    systeminformation: *mut c_void,
    systeminformationlength: u32,
    returnlength: *mut u32,
) -> NTSTATUS;

type NtQueryInformationProcess = unsafe extern "system" fn(
    process_handle: HANDLE,
    process_information_class: u32,
    process_information: PVOID,
    process_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS;

type NtReadVirtualMemory = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    buffer_size: usize,
    number_of_bytes_read: *mut usize,
) -> NTSTATUS;

type NtOpenThread = unsafe extern "system" fn(
    thread_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut CLIENT_ID,
) -> NTSTATUS;

type NtOpenProcess = unsafe extern "system" fn(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut CLIENT_ID,
) -> NTSTATUS;

type NtSuspendThread = unsafe extern "system" fn(thread_handle: HANDLE, previous_suspend_count: *mut u32) -> NTSTATUS;
type NtGetContextThread = unsafe extern "system" fn(thread_handle: HANDLE, context: *mut CONTEXT) -> NTSTATUS;
type NtProtectVirtualMemory = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    number_of_bytes_to_protect: *mut usize,
    new_access_protection: ULONG,
    old_access_protection: *mut ULONG,
) -> NTSTATUS;

type NtWriteVirtualMemory = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    buffer_size: usize,
    number_of_bytes_written: *mut usize,
) -> NTSTATUS;

type NtResumeThread = unsafe extern "system" fn(thread_handle: HANDLE, suspend_count: *mut u32) -> NTSTATUS;
type NtFlushInstructionCache = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: PVOID,
    length: usize,
) -> NTSTATUS;

type NtAllocateVirtualMemory = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    zero_bits: ULONG,
    region_size: *mut SIZE_T,
    allocation_type: ULONG,
    protect: ULONG,
) -> NTSTATUS;

type NtFreeVirtualMemory = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    region_size: *mut SIZE_T,
    free_type: ULONG,
) -> NTSTATUS;

type NtSetContextThread = unsafe extern "system" fn(thread_handle: HANDLE, thread_context: *mut CONTEXT) -> NTSTATUS;
type WaitForSingleObject = unsafe extern "system" fn(
    handle: HANDLE,
    dwMilliseconds: u32,
    
) -> u32;

type NtQueryVirtualMemory = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: PVOID,
    memory_information_class: MEMORY_INFORMATION_CLASS,
    memory_information: PVOID,
    memory_information_length: SIZE_T,
    return_length: *mut SIZE_T,
) -> NTSTATUS;

type NtDelayExecution = unsafe extern "system" fn(
    alertable: bool,
    delay_interval: *mut LARGE_INTEGER,
) -> NTSTATUS;

type NtCreateUserProcess = unsafe extern "system" fn(
    process_handle: *mut HANDLE,
    thread_handle: *mut HANDLE,
    process_desired_access: u32,
    thread_desired_access: u32,
    process_object_attributes: *mut OBJECT_ATTRIBUTES,
    thread_object_attributes: *mut OBJECT_ATTRIBUTES,
    process_flags: u32,
    thread_flags: u32,
    process_parameters: *mut c_void,
    create_info: *mut PS_CREATE_INFO,
    attribute_list: *mut PS_ATTRIBUTE_LIST,

) -> NTSTATUS;

pub fn nt_create_user_process(
    process_handle: *mut HANDLE,
    thread_handle: *mut HANDLE,
    process_desired_access: u32,
    thread_desired_access: u32,
    process_object_attributes: *mut OBJECT_ATTRIBUTES,
    thread_object_attributes: *mut OBJECT_ATTRIBUTES,
    process_flags: u32,
    thread_flags: u32,
    process_parameters: *mut c_void,
    create_info: *mut PS_CREATE_INFO,
    attribute_list: *mut PS_ATTRIBUTE_LIST,
) -> NTSTATUS {
    unsafe {

        initialize_hooks();

        let ret: Option<NTSTATUS>;
        let func_ptr: NtCreateUserProcess;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(
            ntdll,
            &m!("NtCreateUserProcess"),
            func_ptr,
            ret,
            process_handle,
            thread_handle,
            process_desired_access,
            thread_desired_access,
            process_object_attributes,
            thread_object_attributes,
            process_flags,
            thread_flags,
            process_parameters,
            create_info,
            attribute_list
        );

        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }

    }
}

pub fn nt_delay_execution(alertable: bool, delay_interval: *mut LARGE_INTEGER) -> NTSTATUS {
    unsafe {

        initialize_hooks();

        let ret: Option<NTSTATUS>;
        let func_ptr: NtDelayExecution;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(ntdll, &m!("NtDelayExecution"), func_ptr, ret, alertable, delay_interval);

        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }

    }
}


pub fn nt_query_virtual_memory(
    process_handle: HANDLE,
    base_address: PVOID,
    memory_information_class: MEMORY_INFORMATION_CLASS,
    memory_information: PVOID,
    memory_information_length: SIZE_T,
    return_length: *mut SIZE_T,
) -> NTSTATUS {
    unsafe {

        initialize_hooks();

        let ret: Option<NTSTATUS>;
        let func_ptr: NtQueryVirtualMemory;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(
            ntdll,
            &m!("NtQueryVirtualMemory"),
            func_ptr,
            ret,
            process_handle,
            base_address,
            memory_information_class,
            memory_information,
            memory_information_length,
            return_length
        );

        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }

    }
}

pub fn wait_for_single_object(handle: HANDLE, dwMilliseconds: u32) -> u32 {
    unsafe {

        //initialize_hooks();

        let ret: Option<u32>;
        let func_ptr: WaitForSingleObject;
        let kernel32 = dinvoke_rs::dinvoke::get_module_base_address(&m!("kernel32.dll"));
        dinvoke::dynamic_invoke!(kernel32, &m!("WaitForSingleObject"), func_ptr, ret, handle, dwMilliseconds);

        //destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => 0,   // Return a default value if it's None
        }
    }
}

pub fn nt_set_context_thread(thread_handle: HANDLE, thread_context: *mut CONTEXT) -> NTSTATUS {
    unsafe {

        initialize_hooks();

        let ret: Option<NTSTATUS>;
        let func_ptr: NtSetContextThread;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(ntdll, &m!("NtSetContextThread"), func_ptr, ret, thread_handle, thread_context);

        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }

    }
}


pub fn nt_free_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    region_size: *mut SIZE_T,
    free_type: ULONG,
) -> NTSTATUS {
    unsafe {

        initialize_hooks();

        let ret: Option<NTSTATUS>;
        let func_ptr: NtFreeVirtualMemory;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(
            ntdll,
            &m!("NtFreeVirtualMemory"),
            func_ptr,
            ret,
            process_handle,
            base_address,
            region_size,
            free_type
        );

        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }
    }
}

pub fn nt_allocate_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    zero_bits: ULONG,
    region_size: *mut SIZE_T,
    allocation_type: ULONG,
    protect: ULONG,
) -> NTSTATUS {
    unsafe {

        initialize_hooks();

        let ret: Option<NTSTATUS>;
        let func_ptr: NtAllocateVirtualMemory;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(
            ntdll,
            &m!("NtAllocateVirtualMemory"),
            func_ptr,
            ret,
            process_handle,
            base_address,
            zero_bits,
            region_size,
            allocation_type,
            protect
        );

        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }
    }
}

pub fn nt_flush_instruction_cache(process_handle: HANDLE, base_address: PVOID, length: usize) -> NTSTATUS {
    unsafe {

        initialize_hooks();

        let ret: Option<NTSTATUS>;
        let func_ptr: NtFlushInstructionCache;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(ntdll, &m!("NtFlushInstructionCache"), func_ptr, ret, process_handle, base_address, length);

        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }
    }
}

pub fn nt_flush_instruction_cache_unwinder(process_handle: HANDLE, base_address: PVOID, length: usize) -> NTSTATUS {
    unsafe {
        //let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        //let nt_flush_instruction_cache = dinvoke_rs::dinvoke::get_function_address(ntdll, &m!("NtFlushInstructionCache"));

        let ntstatus = unwinder::indirect_syscall!("NtFlushInstructionCache", false, process_handle, base_address, length);
        
        //handle the unwinder result which is a *mut c_void
        let ntstatus = ntstatus as *mut NTSTATUS; //dereference the pointer
        let ntstatus = *ntstatus;
        ntstatus

        
    }

}

pub fn nt_resume_thread(thread_handle: HANDLE, suspend_count: *mut u32) -> NTSTATUS {
    unsafe {

        initialize_hooks();

        let ret: Option<NTSTATUS>;
        let func_ptr: NtResumeThread;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(ntdll, &m!("NtResumeThread"), func_ptr, ret, thread_handle, suspend_count);

        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }
    }
}

pub fn nt_resume_thread_unwinder(thread_handle: HANDLE, suspend_count: *mut u32) -> NTSTATUS {
    unsafe {
        //let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        //let nt_resume_thread = dinvoke_rs::dinvoke::get_function_address(ntdll, &m!("NtResumeThread"));

        let ntstatus = unwinder::indirect_syscall!("NtResumeThread", false, thread_handle, suspend_count);
        
        //handle the unwinder result which is a *mut c_void
        let ntstatus = ntstatus as *mut NTSTATUS; //dereference the pointer
        let ntstatus = *ntstatus;
        ntstatus

        
    }

}

pub fn nt_write_virtual_memory(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    buffer_size: usize,
    number_of_bytes_written: *mut usize,
) -> NTSTATUS {
    unsafe {

        initialize_hooks();

        let ret: Option<NTSTATUS>;
        let func_ptr: NtWriteVirtualMemory;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(
            ntdll,
            &m!("NtWriteVirtualMemory"),
            func_ptr,
            ret,
            process_handle,
            base_address,
            buffer,
            buffer_size,
            number_of_bytes_written
        );

        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }
    }
}

pub fn nt_write_virtual_memory_unwinder(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    buffer_size: usize,
    number_of_bytes_written: *mut usize,
) -> NTSTATUS {
    unsafe {
        //let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        //let nt_write_virtual_memory = dinvoke_rs::dinvoke::get_function_address(ntdll, &m!("NtWriteVirtualMemory"));

        let ntstatus = unwinder::indirect_syscall!("NtWriteVirtualMemory", false, process_handle, base_address, buffer, buffer_size, number_of_bytes_written);
        
        //handle the unwinder result which is a *mut c_void
        let ntstatus = ntstatus as *mut NTSTATUS; //dereference the pointer
        let ntstatus = *ntstatus;
        ntstatus

        
    }

}

pub fn nt_protect_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    number_of_bytes_to_protect: *mut SIZE_T,
    new_access_protection: ULONG,
    old_access_protection: *mut ULONG,
) -> NTSTATUS {
    unsafe {

        initialize_hooks();

        let ret: Option<NTSTATUS>;
        let func_ptr: NtProtectVirtualMemory;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(
            ntdll,
            &m!("NtProtectVirtualMemory"),
            func_ptr,
            ret,
            process_handle,
            base_address,
            number_of_bytes_to_protect,
            new_access_protection,
            old_access_protection
        );

        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }
    }
}

pub fn nt_protect_virtual_memory_unwinder(
    process_handle: HANDLE,
    base_address: *mut PVOID,
    number_of_bytes_to_protect: *mut SIZE_T,
    new_access_protection: ULONG,
    old_access_protection: *mut ULONG,
) -> NTSTATUS {
    unsafe {
        //let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        //let nt_protect_virtual_memory = dinvoke_rs::dinvoke::get_function_address(ntdll, &m!("NtProtectVirtualMemory"));

        let ntstatus = unwinder::indirect_syscall!("NtProtectVirtualMemory", false, process_handle, base_address, number_of_bytes_to_protect, new_access_protection, old_access_protection);
        
        //handle the unwinder result which is a *mut c_void
        let ntstatus = ntstatus as *mut NTSTATUS; //dereference the pointer
        let ntstatus = *ntstatus;
        ntstatus

        
    }

}

pub fn nt_get_context_thread(thread_handle: HANDLE, context: *mut CONTEXT) -> NTSTATUS {
    unsafe {

        initialize_hooks();

        let ret: Option<NTSTATUS>;
        let func_ptr: NtGetContextThread;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(ntdll, &m!("NtGetContextThread"), func_ptr, ret, thread_handle, context);

        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }
    }
}

pub fn nt_get_context_thread_unwinder(thread_handle: HANDLE, context: *mut CONTEXT) -> NTSTATUS {
    unsafe {
        //let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        //let nt_get_context_thread = dinvoke_rs::dinvoke::get_function_address(ntdll, &m!("NtGetContextThread"));

        let ntstatus = unwinder::indirect_syscall!("NtGetContextThread", false, thread_handle, context);
        
        //handle the unwinder result which is a *mut c_void
        let ntstatus = ntstatus as *mut NTSTATUS; //dereference the pointer
        let ntstatus = *ntstatus;
        ntstatus

        
    }

}

pub fn nt_suspend_thread(thread_handle: HANDLE, previous_suspend_count: *mut u32) -> NTSTATUS {

    //initialize_hooks();
    unsafe {

        initialize_hooks();

        let ret: Option<NTSTATUS>;
        let func_ptr: NtSuspendThread;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(ntdll, &m!("NtSuspendThread"), func_ptr, ret, thread_handle, previous_suspend_count);

        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }
    }
    //destroy_hooks();
}

pub fn nt_suspend_thread_unwinder(thread_handle: HANDLE, previous_suspend_count: *mut u32) -> NTSTATUS {
    unsafe {
        //let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        //let nt_suspend_thread = dinvoke_rs::dinvoke::get_function_address(ntdll, &m!("NtSuspendThread"));

        let ntstatus = unwinder::indirect_syscall!("NtSuspendThread", false, thread_handle, previous_suspend_count);
        
        //handle the unwinder result which is a *mut c_void
        let ntstatus = ntstatus as *mut NTSTATUS; //dereference the pointer
        let ntstatus = *ntstatus;
        ntstatus

        
    }

}


pub fn nt_open_process(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut CLIENT_ID,
) -> NTSTATUS {
    unsafe {

        initialize_hooks();

        let ret: Option<NTSTATUS>;
        let func_ptr: NtOpenProcess;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(
            ntdll,
            &m!("NtOpenProcess"),
            func_ptr,
            ret,
            process_handle,
            desired_access,
            object_attributes,
            client_id
        );

        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }

        
    }
}

pub fn nt_open_thread(
    thread_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut CLIENT_ID,
) -> NTSTATUS {
    unsafe {

        initialize_hooks();

        let ret: Option<NTSTATUS>;
        let func_ptr: NtOpenThread;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(
            ntdll,
            &m!("NtOpenThread"),
            func_ptr,
            ret,
            thread_handle,
            desired_access,
            object_attributes,
            client_id
        );

        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }

        
    }
}

pub fn nt_read_virtual_memory_unwinder(process_handle: HANDLE, base_address: PVOID, buffer: PVOID, buffer_size: usize, bytes_read: *mut usize) -> NTSTATUS {
    unsafe {
        //let ret: Option<NTSTATUS>;
       // let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));

        let ntstatus = unwinder::indirect_syscall!("NtReadVirtualMemory", false, process_handle, base_address, buffer, buffer_size, bytes_read);
        
        //handle the unwinder result which is a *mut c_void
        let ntstatus = ntstatus as *mut NTSTATUS; //dereference the pointer
        let ntstatus = *ntstatus;
        ntstatus

        
    }

}

pub fn nt_read_virtual_memory(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    buffer_size: usize,
    number_of_bytes_read: *mut usize,
) -> NTSTATUS {
    unsafe {

        initialize_hooks();

        let ret: Option<NTSTATUS>;
        let func_ptr: NtReadVirtualMemory;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(
            ntdll,
            &m!("NtReadVirtualMemory"),
            func_ptr,
            ret,
            process_handle,
            base_address,
            buffer,
            buffer_size,
            number_of_bytes_read
        );
        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }
    }
}

pub fn nt_query_information_process(
    process_handle: HANDLE,
    process_information_class: u32,
    process_information: PVOID,
    process_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    unsafe {

        initialize_hooks();

        let ret: Option<NTSTATUS>;
        let func_ptr: NtQueryInformationProcess;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(
            ntdll,
            &m!("NtQueryInformationProcess"),
            func_ptr,
            ret,
            process_handle,
            process_information_class,
            process_information,
            process_information_length,
            return_length
        );
        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }
    }
}

pub fn nt_close_unwinder(handle: HANDLE) -> NTSTATUS {
    unsafe {
        //let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        //let nt_close = dinvoke_rs::dinvoke::get_function_address(ntdll, &m!("NtClose"));

        let ntstatus = unwinder::indirect_syscall!("NtClose", false, handle);
        
        //handle the unwinder result which is a *mut c_void
        let ntstatus = ntstatus as *mut NTSTATUS; //dereference the pointer
        let ntstatus = *ntstatus;
        ntstatus

        
    }

}


pub fn nt_close(handle: HANDLE) -> i32 {
    unsafe {

        initialize_hooks();
        let ret: Option<i32>;
        let func_ptr: NtClose;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(ntdll, &m!("NtClose"), func_ptr, ret, handle);

        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }
    }
}

pub fn nt_query_system_information(
    systeminformationclass: SYSTEM_INFORMATION_CLASS,
    systeminformation: *mut c_void,
    systeminformationlength: u32,
    returnlength: *mut u32,
) -> NTSTATUS {
    unsafe {

        initialize_hooks();
        let ret: Option<NTSTATUS>;
        let func_ptr: NtQuerySystemInformation;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(
            ntdll,
            &m!("NtQuerySystemInformation"),
            func_ptr,
            ret,
            systeminformationclass,
            systeminformation,
            systeminformationlength,
            returnlength
        );
        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }
    }
}

pub fn nt_duplicate_object(
    source_process_handle: HANDLE,
    source_handle: HANDLE,
    target_process_handle: HANDLE,
    target_handle: *mut HANDLE,
    desired_access: u32,
    handleattributes: u32,
    options: u32,
) -> NTSTATUS {
    unsafe {

        initialize_hooks();
        let ret: Option<NTSTATUS>;
        let func_ptr: NtDuplicateObject;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&m!("ntdll.dll"));
        dinvoke::dynamic_invoke!(
            ntdll,
            &m!("NtDuplicateObject"),
            func_ptr,
            ret,
            source_process_handle,
            source_handle,
            target_process_handle,
            target_handle,
            desired_access,
            handleattributes,
            options
        );
        destroy_hooks();

        match ret {
            Some(x) => x, // Return the value if it's Some
            None => -1,   // Return a default value if it's None
        }
    }
}

