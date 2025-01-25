### snapinject_rs

A process injection using process snapshotting based on https://gitlab.com/ORCA000/snaploader , in rust.

~~This is a PoC version. It does not use dynamic resolution of API calls, etc...~~

This OSPEC branch uses dynamic resolution of API calls, and is more secure. A list of changes:

- uses dynamic resolution of all API calls with noldr (https://github.com/Teach2Breach/noldr)
- implements litcrypt for every compatible string
- renamed functions to be less conspicious
- refactored the code to keep functions private and only expose a public wrapper function
- general cleanup and good practices

note: I'll do a dinvoke version of this soon for another opsec focused version.

#### Usage

This program can be compiled as an exe, or used as a library in other rust programs.

To use as an exe, swap the SHELL_CODE in main.rs with your own shellcode and compile.

To use as a library, add the following to your `Cargo.toml`:

```toml
[dependencies]
snapinject_rs = { git = "https://github.com/Teach2Breach/snapinject_rs" }
```
Call the snapin function with your process name and shellcode.

```rust
snapinject_rs::snapin(&process_name, &SHELL_CODE).unwrap();
```

#### Credits

- This project is a derivative work based on [snaploader](https://gitlab.com/ORCA000/snaploader), which is also licensed under the MIT License.
