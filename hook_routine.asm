

hook SEGMENT BYTE READ WRITE EXECUTE

hook_segment_start = $

HookObject_HookRoutine DQ 0

HookObject_rsp DQ 0
HookObject_rbp DQ 0
HookObject_rax DQ 0

HookObject_rcx DQ 0
HookObject_rdx DQ 0
HookObject_r8 DQ 0
HookObject_r9 DQ 0

HookObject_OriginalAddress DQ 0
HookObject_ReturnAddress DQ 0

HookObject_Id dw 0
HookObject_Flags dw 0
HookObject_BackupSize dw 0
HookObject_MaxCallBacks dw 0

__HookObject_BackupCode:
HookObject_BackupCode DB 30h DUP(0)

HookObject_CallBacks DQ 0

mem_type DQ 0

PUBLIC __hook_segment_size
__hook_segment_size DQ hook_segment_size

PUBLIC __hook_routine_offs
__hook_routine_offs DQ HookRoutineOffset

PUBLIC __hook_segment_address
__hook_segment_address DQ hook_segment_start

Var001 DD 0
bPostCalled DD 0

HookRoutineOffset = $ - hook_segment_start
HookRoutine proc

;-------- prologue --------

mov eax, [bPostCalled]
test eax, eax
jnz PostCalled1

;--------------------------

mov [HookObject_rsp], rsp
mov [HookObject_rbp], rbp
mov [HookObject_r9], r9
mov [HookObject_r8], r8
mov [HookObject_rdx], rdx 
mov [HookObject_rcx], rcx

mov rax, [rsp]
mov qword ptr [HookObject_ReturnAddress], rax 

movzx rax, word ptr [HookObject_Flags]
and al, 1 ;HOOK_FLAG_POST
test al, al
jne	PostCall		;Yes

PostCalled1:

mov dword ptr [Var001], 0

loop01:
xor rax, rax
mov eax, [Var001]
cmp ax, word ptr [HookObject_MaxCallBacks]
jae loop01_break

mov rsp, [HookObject_rsp]

mov r9, [HookObject_r9]
mov r8, [HookObject_r8] 
mov rdx, [HookObject_rdx] 
mov rcx, [HookObject_rcx]

mov rbp, [HookObject_CallBacks]
mov rax, [rbp+rax*8]
test rax, rax
jz null_callbacks

add rsp, 8h
call rax ;callbacks

null_callbacks:
inc dword ptr [Var001]
jmp loop01

loop01_break:

mov eax, [bPostCalled]
test eax, eax
jnz PostCalled2

mov ax, [HookObject_Flags]
and al, 2 ;HOOK_FLAG_IGNORE
test al, al
jne	Ignore		;Yes

mov rsp, [HookObject_rsp]
mov rbp, [HookObject_rbp]
mov rax, [HookObject_rax]

mov rcx, [HookObject_ReturnAddress]
mov [rsp], rcx

mov r9, [HookObject_r9]
mov r8, [HookObject_r8] 
mov rdx, [HookObject_rdx] 
mov rcx, [HookObject_rcx]
jmp __HookObject_BackupCode

PostCall:
	mov dword ptr [bPostCalled], 1
	mov rax, HookRoutine
	mov [rsp], rax
	jmp __HookObject_BackupCode

PostCalled2:
Ignore:
	mov rsp, [HookObject_rsp]
	mov rbp, [HookObject_rbp]
	mov rax, [HookObject_rax]

	mov rcx, [HookObject_ReturnAddress]
	mov [rsp], rcx

	mov r9, [HookObject_r9]
	mov r8, [HookObject_r8] 
	mov rdx, [HookObject_rdx] 
	mov rcx, [HookObject_rcx]
	ret
HookRoutine endp

hook_segment_size = $ - hook_segment_start

hook ENDS

end
