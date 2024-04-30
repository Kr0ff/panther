#pragma once

#include "headers.h"
#include "helpers.h"
#include "defs.h"
#include "rc4.h"

BOOL f_SysCrypt032(void* addrMem, DWORD sizeMem, char* key, SIZE_T sizeKey);

BOOL f_SysCrypt032(void* addrMem, DWORD sizeMem, char* key, SIZE_T sizeKey) {

	BOOL res = FALSE;

	ustring _data;
	ustring _key;
	
	t_FreeLibrary C_FreeLibrary = (t_FreeLibrary)C_GetProcAddr(C_GetModuleHandle(wstrkernel32), strFreeLibrary);
	t_LoadLibraryW C_LoadLibraryW = (t_LoadLibraryW)C_GetProcAddr(C_GetModuleHandle(wstrkernel32), strLoadLibraryW);

	HMODULE hAdvapi32 = C_LoadLibraryW(wstradvapi32dll);

	_data.Buffer = (PUCHAR)addrMem;
	_data.Length = sizeMem;

	_key.Buffer = (PUCHAR)key;
	_key.Length = (DWORD)sizeKey;
	
	NTSTATUS status = NULL;

	status = SystemFunction032(&_data, &_key);
	if (status == STATUS_SUCCESS) {
		res = TRUE;
	}
	else {
		return res;
	}

	C_FreeLibrary(hAdvapi32);
	
	return res;
	

}