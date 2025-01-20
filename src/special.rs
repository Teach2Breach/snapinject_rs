#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(improper_ctypes_definitions)]
#[allow(unused_variables)]

use noldr::{get_function_address, RTL_USER_PROCESS_PARAMETERS, UNICODE_STRING};

use ntapi::ntpsapi::{
    PS_ATTRIBUTE_u, PsCreateInitialState, PS_ATTRIBUTE, PS_ATTRIBUTE_IMAGE_NAME, PS_CREATE_INFO,
};
use ntapi::ntrtl::RTL_USER_PROC_PARAMS_NORMALIZED;


use std::mem::zeroed;
use std::ptr::{self, null_mut};
use winapi::ctypes::c_void;
use winapi::shared::basetsd::SIZE_T;
//use winapi::shared::ntdef::HANDLE as winapi_HANDLE;
use winapi::shared::ntdef::NT_SUCCESS;
use winapi::um::winnt::{PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS};
//use windows::Win32::Foundation::HANDLE;
//we need the old version. fuck you windows.
use windows_0_51::Win32::Foundation::HANDLE as HANDLE;

#[repr(C)]
struct PsAttributeList {
    total_length: SIZE_T,
    attributes: [PS_ATTRIBUTE; 2],
}

const NORMAL_PRIORITY_CLASS: u32 = 0x00000020;
const DETACHED_PROCESS: u32 = 0x00000008;
const DEBUG_PROCESS: u32 = 0x00000001;

//create suspended process with NtCreateUserProcess
pub extern "C" fn CreateSuspendedProcess(ntdll: *const std::ffi::c_void, process_path: &str) -> (HANDLE, HANDLE) {
    unsafe {
        //locate NtCreateUserProcess
        let function_address = get_function_address(ntdll, "NtCreateUserProcess").unwrap();
        let NtCreateUserProcess = std::mem::transmute::<
            _,
            extern "system" fn(
                ProcessHandle: *mut HANDLE,
                ThreadHandle: *mut HANDLE,
                ProcessDesiredAccess: u32,
                ThreadDesiredAccess: u32,
                ProcessObjectAttributes: *mut c_void,
                ThreadObjectAttributes: *mut c_void,
                ProcessFlags: u32,
                ThreadFlags: u32,
                ProcessParameters: *mut c_void,
                CreateInfo: *mut PS_CREATE_INFO,
                AttributeList: *mut PsAttributeList,
            ) -> i32,
        >(function_address);
        println!("NtCreateUserProcess: {:?}", NtCreateUserProcess);

        //locate RtlInitUnicodeString
        let function_address = get_function_address(ntdll, "RtlInitUnicodeString").unwrap();
        let RtlInitUnicodeString = std::mem::transmute::<
            _,
            extern "system" fn(*mut UNICODE_STRING, *const u16),
        >(function_address);
        println!("RtlInitUnicodeString: {:?}", RtlInitUnicodeString);

        //locate RtlCreateProcessParametersEx
        let function_address = get_function_address(ntdll, "RtlCreateProcessParametersEx").unwrap();
        let RtlCreateProcessParametersEx = std::mem::transmute::<
            _,
            extern "system" fn(
                *mut *mut RTL_USER_PROCESS_PARAMETERS, // pProcessParameters
                *mut UNICODE_STRING,                   // ImagePathName
                *mut UNICODE_STRING,                   // DllPath
                *mut UNICODE_STRING,                   // CurrentDirectory
                *mut UNICODE_STRING,                   // CommandLine
                *mut c_void,                           // Environment
                *mut UNICODE_STRING,                   // WindowTitle
                *mut UNICODE_STRING,                   // DesktopInfo
                *mut UNICODE_STRING,                   // ShellInfo
                *mut UNICODE_STRING,                   // RuntimeData
                u32,                                   // Flags
            ) -> i32,
        >(function_address);
        println!(
            "RtlCreateProcessParametersEx: {:?}",
            RtlCreateProcessParametersEx
        );

        let nt_image_path = format!(r"\??\\{}", process_path);
        let mut nt_image_path: Vec<u16> = nt_image_path.encode_utf16().collect();
        nt_image_path.push(0);

        let mut nt_image_path_unicode: UNICODE_STRING = std::mem::zeroed();
        RtlInitUnicodeString(&mut nt_image_path_unicode, nt_image_path.as_ptr());

        let mut process_params: *mut RTL_USER_PROCESS_PARAMETERS = null_mut();
        let status = RtlCreateProcessParametersEx(
            &mut process_params,
            &mut nt_image_path_unicode,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            RTL_USER_PROC_PARAMS_NORMALIZED,
        );

        if !NT_SUCCESS(status) {
            println!("err 1: {:x}", status);
            return (HANDLE(0), HANDLE(0));
        }

        let mut create_info: PS_CREATE_INFO = zeroed();
        create_info.Size = std::mem::size_of::<PS_CREATE_INFO>();
        create_info.State = PsCreateInitialState;

        let ps_attribute = PS_ATTRIBUTE {
            Attribute: PS_ATTRIBUTE_IMAGE_NAME,
            Size: nt_image_path_unicode.Length as usize,
            u: PS_ATTRIBUTE_u {
                ValuePtr: nt_image_path_unicode.Buffer as *mut _,
            },
            ReturnLength: ptr::null_mut(),
        };

        let empty_attr: PS_ATTRIBUTE = zeroed();
        let ps_attribute_list = PsAttributeList {
            total_length: std::mem::size_of::<PsAttributeList>() - size_of::<PS_ATTRIBUTE>(), // 40 (72 - 32)
            attributes: [ps_attribute, empty_attr], // Only include the first attribute here
        };

        let ps_attribute_list = std::mem::transmute(&ps_attribute_list);
        let create_info = std::mem::transmute(&create_info);

        let mut process_handle: HANDLE = HANDLE(0);
        let mut thread_handle: HANDLE = HANDLE(0);
        let process_handle_ptr = &mut process_handle as *mut HANDLE;
        let thread_handle_ptr = &mut thread_handle as *mut HANDLE;

        let status = NtCreateUserProcess(
            process_handle_ptr,
            thread_handle_ptr,
            PROCESS_ALL_ACCESS,
            THREAD_ALL_ACCESS,
            null_mut(),
            null_mut(),
            0,
            1,
            process_params as *mut c_void,
            create_info,
            ps_attribute_list,
        );

        if !NT_SUCCESS(status) {
            println!("err 2: {:x}", status);
            return (HANDLE(0), HANDLE(0));
        }

        // Set process priority class
        let function_address = get_function_address(ntdll, "NtSetInformationProcess").unwrap();
        let NtSetInformationProcess: extern "system" fn(
            ProcessHandle: HANDLE,
            ProcessInformationClass: u32,
            ProcessInformation: *const c_void,
            ProcessInformationLength: u32,
        ) -> i32 = std::mem::transmute(function_address);

        let priority_class = NORMAL_PRIORITY_CLASS | DETACHED_PROCESS | DEBUG_PROCESS;
        let status = NtSetInformationProcess(
            process_handle,
            12, 
            &priority_class as *const u32 as *const c_void,
            std::mem::size_of::<u32>() as u32,
        );

        if !NT_SUCCESS(status) {
            println!("Failed to set process attributes: {:x}", status);
            // Continue anyway since the process is created
        }

        //need to check if the process has the right attributes set now and if it's suspended

        (process_handle, thread_handle)
    }
}