#pragma once

#include "headers.h"

#define STRUCTS

HMODULE C_GetModuleHandle(LPCWSTR lpModuleName);

HMODULE C_GetModuleHandle(LPCWSTR lpModuleName) {

    HMODULE moduleHandle = NULL;

#ifdef _WIN64
    PPEB			pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
    PPEB			pPeb = (PEB*)(__readfsdword(0x30));
#endif

    PPEB_LDR_DATA pLdr = pPeb->LdrData;

    PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pLdr->InMemoryOrderModuleList.Flink;

    while (pLdrDataTableEntry) {

        if (pLdrDataTableEntry->FullDllName.Length != NULL) {

            if (lstrcmpiW((LPCWSTR)pLdrDataTableEntry->FullDllName.Buffer, lpModuleName) == 0) {
                
#ifdef STRUCTS
                return (HMODULE)(pLdrDataTableEntry->InInitializationOrderLinks.Flink);
#else
                return (HMODULE)pLdrDataTableEntry->Reserved2[0];
#endif
            }

        }
        else {
            break;
        }

        pLdrDataTableEntry = *(PLDR_DATA_TABLE_ENTRY*)(pLdrDataTableEntry);

    }

    return NULL;

}

//--------------------------------------------------

FARPROC C_GetProcAddr(HMODULE lphModule, LPCSTR lpFunctionName);

FARPROC C_GetProcAddr(HMODULE lphModule, LPCSTR lpFunctionName) {

    FARPROC pFunctionAddress = NULL;

    HMODULE pBase = lphModule;

    if (pBase == NULL)
    {
        return NULL;
    }

    PIMAGE_DOS_HEADER pDosHeaders = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((unsigned char*)pDosHeaders + pDosHeaders->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeaders = (PIMAGE_OPTIONAL_HEADER)&pNtHeaders->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDirectory = &(pOptionalHeaders->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((unsigned char*)pBase + pDataDirectory->VirtualAddress);

    DWORD numberOfNames = pExportDirectory->NumberOfNames;

    PDWORD ExportAddressTable = (PDWORD)((unsigned char*)pBase + pExportDirectory->AddressOfFunctions);

    PWORD NameOrdinalArrays = (PWORD)((unsigned char*)pBase + pExportDirectory->AddressOfNameOrdinals);

    PDWORD exportNamePointerTable = (PDWORD)((unsigned char*)pBase + pExportDirectory->AddressOfNames);

    DWORD FunctionNameIndex = 0;
    for (FunctionNameIndex = 0; FunctionNameIndex < numberOfNames; FunctionNameIndex++)
    {

        char* ModuleFunctionName = (char*)((unsigned char*)pBase + exportNamePointerTable[FunctionNameIndex]);
        if (lstrcmpiA(lpFunctionName, ModuleFunctionName) == 0)
        {
            WORD ordinal = NameOrdinalArrays[FunctionNameIndex];
            PDWORD targetFunctionAddress = (PDWORD)((unsigned char*)pBase + ExportAddressTable[ordinal]); 
            pFunctionAddress = (FARPROC)targetFunctionAddress;
        }
    }

    if (pFunctionAddress == NULL) {
        return NULL;
    }
    else {
        return pFunctionAddress;
    }
}