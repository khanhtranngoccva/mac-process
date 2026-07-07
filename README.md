# mac-process

This is a divergent fork/port of [libproc-rs](https://github.com/andrewdavidmackenzie/libproc-rs/) for getting information and verifying the integrity of macOS processes that diverges from the original libproc source code.

## Comparison
- Focuses mainly on macOS-specific functionality, while other OSes are not supported (Linux users should use `procfs`, which provide a similar interface to this crate using `/proc/{pid}`). 
- Supports a higher-level construct with the help of Mach functions, libproc functions, and the kqueue API:
    - The `ProcessMonitor` object yields shared, (practically) race-free handles to live processes.
    - Process exit notifications are supported.
    - To avoid race conditions due to PID reuse, dead processes cannot be queried (if they happen to be queried, the results are ignored).
- All errors are converted to `std::io::Error`, and certain items in low-level libraries are also parsed into Rust types.
- Caching of certain immutable fields is supported - this is useful when a user needs to query the same process multiple times.
- Supports opening the main executable over `/.vol` for checking its contents (e.g. MD5 and SHA256 hashes).

## Credits
Certain parts of this codebase are directly reused here.
- [libproc-rs](https://github.com/andrewdavidmackenzie/libproc-rs/) by [andrewdavidmackenzie](https://github.com/andrewdavidmackenzie)
- [endpoint-sec](https://github.com/HarfangLab/endpoint-sec) by [HarfangLab](https://github.com/HarfangLab)

## More information (testing, building)
See the original repo (https://github.com/andrewdavidmackenzie/libproc-rs) for more details. Information related to Linux is not applicable in this crate. 

## TODO
- Introduce signature verification for MacOS binaries
- Discuss re-merging with `libproc-rs` for completeness
- Figure out whether custom error types are needed

## LICENSE
This code is licensed under MIT license (see LICENSE.md).