#pragma once

#include "headers.h"
#include "defs.h"
#include "customs.h"

FARPROC GetK32APIAddress(char* APIName);
FARPROC GetNTAPIAddress(char* APIName);

PVOID ZwMoveMemory(
	_Inout_ PVOID dest,
	_In_    const PVOID src,
	_In_    SIZE_T len
);

FARPROC GetK32APIAddress(char* APIName) {

	FARPROC addr = NULL;
	HMODULE hModule = NULL;

	hModule = C_GetModuleHandle(wstrkernel32);
	if (hModule == NULL) {
		return NULL;
	}

	addr = C_GetProcAddr(hModule, APIName);
	if (addr == NULL) {
		return NULL;
	}

	return addr;
}

FARPROC GetNTAPIAddress(char* APIName) {

	FARPROC addr = NULL;
	HMODULE hModule = NULL;

	hModule = C_GetModuleHandle(wstrntdll);
	if (hModule == NULL) {
		return NULL;
	}

	addr = C_GetProcAddr(hModule, APIName);
	if (addr == NULL) {
		return NULL;
	}

	return addr;

	return NULL;
}
 
PVOID ZwMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
	char* d = (char*)dest;
	char* s = (char*)src;

	if (d < s)
		while (len--)
			*d++ = *s++;
	else {
		char* lasts = s + (len - 1);
		char* lastd = d + (len - 1);
		while (len--)
			*lastd-- = *lasts--;
	}
	return dest;
}