# Project Ares

## Project Ares Injector

Project Ares Injector is a Proof of Concept (PoC) loader written in C/C++ based on the [Transacted Hollowing](https://github.com/hasherezade/transacted_hollowing) technique. The loader injects a PE into a remote process and features:

* PPID spoofing
* CIG to block non-Microsoft-signed binaries
* Dynamic function resolution without `LoadLibrary()` or `GetProcAddress()` APIs
* API hashing
* Unhooks NTDLL by refreshing the `.text` section with a clean version from disk
* Minimized use of WIN32 APIs
* Basic sandbox detection
* AES256 CBC encrypted payload loaded from PE resources

The loader is currently only 64-bit and only supports 64-bit payloads.

## Project Ares Cryptor

Cryptor is a basic console application meant to encrypt the payload before adding it as a PE resource to the Injector.
It takes a single `<filepath>` argument to the payload on disk, which is then encrypted and written to disk as `payload.bin`.

## Usage

1. Change the encryption key in Injector/main.cpp at line 329 to a 16-byte value
2. Change the encryption key in Cryptor/main.cpp at line 34 to match the encryption key in Injector

Optionally, the initialization vectors can be modified, they should be 16-bytes as well:
```c++
const uint8_t iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
```

3. Use `Cryptor.exe` to encrypt your x64 payload of choice
4. Add `payload.bin` as a resource to Injector, make sure to name it `payload_bin` or modify Injector/main.cpp line 324 to match the given name:
```c++
HRSRC rc = FindResource(NULL, MAKEINTRESOURCE(IDR_PAYLOAD_BIN1), L"PAYLOAD_BIN");
```

5. Profit

Note:
> The default spawned process is `svchost.exe`
> The default spoofed parent process is `explorer.exe`