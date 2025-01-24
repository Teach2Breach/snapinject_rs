swapping out windows api imports with dynamically resolve NT API calls
need to fix handle types for snap_thread_hijack
//need to check if the process has the right attributes set now and if it's suspended
see http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FProcess%2FPROCESS_INFORMATION_CLASS.html

going to swap it back to CreateProcess and take the NtCreateUserProcess stuff out into a seperate project since it is going to take a while. At least I can get the dynamic resolve stuff working. When the new NtCreateUserProcess project with ability to set process attributes is done, I can swap it back in.

dynamic resolve is working, done for CreateProcessA, need to do for other functions and then clean up the code
updated PssCaptureSnapshot to use the dynamic resolve stuff, need to do for other functions 
remember to also remove winapi::um::errhandlingapi::GetLastError()

finished with dynamic resolve for snap_thread_hijack
next going to work on doing the same for get_hidden_injection_address, but first need to pass the teb to it
im on line 163 of func.rs
im on line 310 of func.rs
line 391 of func.rs
