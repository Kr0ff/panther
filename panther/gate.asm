.data
	wSystemCall DWORD 000h

.code 
	CreateGate PROC
		nop
		nop
		nop
		mov wSystemCall, 000h
		nop
		nop
		nop
		mov wSystemCall, ecx
		nop
		nop
		nop
		ret
	CreateGate ENDP

	GateDescent PROC
		nop
		nop
		nop
		mov rax, rcx
		nop
		nop
		nop
		mov r10, rax
		nop
		nop
		nop
		mov eax, wSystemCall
		nop
		nop
		nop
		syscall
		ret
	GateDescent ENDP
end