### snapinject_rs

A process injection using process snapshotting based on https://gitlab.com/ORCA000/snaploader , in rust.

This is a PoC version. It does not use dynamic resolution of API calls, etc...

#### Usage

This program can be compiled as an exe, or used as a dll. It can also be used as a library in other rust programs.

To use as an exe or dll, swap the SHELL_CODE in main.rs with your own shellcode.

To use as a library, add the following to your `Cargo.toml`:

```toml
[dependencies]
snapinject_rs = { git = "https://github.com/Teach2Breach/snapinject_rs" }
```
Call the inject_shellcode function with your process name and shellcode.

```rust
snapinject_rs::inject_shellcode(&process_name, &SHELL_CODE).unwrap();
```

#### Notes

I left a bunch of commented out code in the main.rs that shows how to use some of the functions individually. I also left in a bunch of commented out print statements that may be useful for debugging and understanding the code.

#### Credits

- This project is a derivative work based on [snaploader](https://gitlab.com/ORCA000/snaploader), which is also licensed under the MIT License.
