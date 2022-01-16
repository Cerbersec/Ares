#ifndef _HEADERS_H
#define _HEADERS_H

#pragma once
#include <windows.h>

#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_IMAGE_NOT_AT_BASE 0x40000003

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

typedef NTSTATUS(NTAPI* PNtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS(NTAPI* PNtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* PNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef NTSTATUS(NTAPI* PNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* PNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* PNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* PNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* PNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);
typedef NTSTATUS(NTAPI* PNtClose)(HANDLE);
typedef void(NTAPI* PRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI* PNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* PNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
typedef NTSTATUS(NTAPI* PNtCreateTransaction)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING);
typedef BOOL(NTAPI* PRtlSetCurrentTransaction)(HANDLE);
typedef NTSTATUS(NTAPI* PNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* PNtWriteFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS(NTAPI* PNtRollbackTransaction)(HANDLE, BOOLEAN);
typedef NTSTATUS(NTAPI* PNtGetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS(NTAPI* PNtSetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS(NTAPI* PNtResumeThread)(HANDLE, PULONG);

unsigned int hash(const char*);
PVOID GetNTDLLAddr();
BOOL CheckSandbox(PNtDelayExecution);
HANDLE GetParentHandle(PWSTR, PNtOpenProcess, PNtClose);
PROCESS_INFORMATION SpawnProc(LPSTR, HANDLE);
BOOL Unhook(PVOID, PRtlInitUnicodeString, PNtOpenFile, PNtCreateSection, PNtMapViewOfSection, PNtUnmapViewOfSection, PNtProtectVirtualMemory, PNtClose);
BOOL Cleanup(PNtClose fpNtClose, PNtResumeThread fpNtResumeThread, HANDLE hThread);
#endif