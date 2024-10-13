

.code

HookObject_HookRoutine = 0
HookObject_rsp = 8   ;use
HookObject_rbp = 10h ;use
HookObject_rsi = 18h ;use
HookObject_rax = 20h ;use
HookObject_OriginalAddress = 28h 
HookObject_ReturnAddress = 30h ;use
HookObject_Id = 38h ;WORD
HookObject_Flags = 3Ah ;WORD
HookObject_BackupSize = 3Ch ;WORD
HookObject_MaxCallBacks = 3Eh ;WORD
HookObject_BackupCode = 40h
HookObject_CallBack_Func = HookObject_BackupCode + 30h

HookRoutine_Post proc

mov qword ptr [rbp+HookObject_rax], rax

sub rsp, 10h
mov qword ptr [rsp], 0

loop01:
mov rax, [rsp]
cmp ax, word ptr [rbp+HookObject_MaxCallBacks]
jae loop01_break

mov rsp, [rbp+HookObject_rsp]
mov r9, [rsp+20h]
mov r8, [rsp+18h] 
mov rdx, [rsp+10h] 
mov rcx, [rsp+8]

lea rax, [rbp + HookObject_CallBack_Func + rax*8]
mov rax, [rax]
test rax, rax
jz null_callbacks

add rsp, 8h
call rax ;callbacks
sub rsp, 8h

null_callbacks:
sub rsp, 10h
inc qword ptr [rsp]
jmp loop01

loop01_break:

add rsp, 10h

mov rcx, rbp
mov rsp, [rcx+HookObject_rsp]
mov rbp, [rcx+HookObject_rbp]
	
mov rsi, [rcx+HookObject_ReturnAddress]
mov [rsp], rsi

mov rsi, [rcx+HookObject_rsi]
mov rax, [rcx+HookObject_rax]
ret
HookRoutine_Post endp

public HookRoutine
HookRoutine proc

mov [rax+HookObject_rsp], rsp
mov [rax+HookObject_rbp], rbp
mov [rax+HookObject_rsi], rsi

mov [rsp+20h], r9
mov [rsp+18h], r8
mov [rsp+10h], rdx 
mov [rsp+8], rcx

mov rbp, rax

mov rax, [rsp]
mov qword ptr [rbp+HookObject_ReturnAddress], rax 

movzx rax, word ptr [rbp+HookObject_Flags]
and al, 1 ;HOOK_FLAG_POST
test al, al
jne	PostCall		;Yes

sub rsp, 10h
mov qword ptr [rsp], 0

loop01:
mov rax, [rsp]
cmp ax, word ptr [rbp+HookObject_MaxCallBacks]
jae loop01_break

mov rsp, [rbp+HookObject_rsp]
mov r9, [rsp+20h]
mov r8, [rsp+18h] 
mov rdx, [rsp+10h] 
mov rcx, [rsp+8]

lea rax, [rbp + HookObject_CallBack_Func + rax*8]
mov rax, [rax]
test rax, rax
jz null_callbacks

add rsp, 8h
call rax ;callbacks
sub rsp, 8h

null_callbacks:
sub rsp, 10h
inc qword ptr [rsp]
jmp loop01

loop01_break:

add rsp, 10h

mov rax, [rbp+HookObject_Flags]
and al, 2 ;HOOK_FLAG_IGNORE
test al, al
jne	Ignore		;Yes

mov rcx, rbp
mov rsp, [rcx+HookObject_rsp]
mov rbp, [rcx+HookObject_rbp]
mov rsi, [rcx+HookObject_rsi]
mov rax, [rcx+HookObject_rax]
lea rcx, [rcx+HookObject_BackupCode]
jmp rcx

PostCall:
	add rsp, 8
	mov rax, HookRoutine_Post
	push rax
	lea rax, [rbp+HookObject_BackupCode]
	jmp rax

Ignore:
	mov rcx, rbp
	mov rsp, [rcx+HookObject_rsp]
	mov rbp, [rcx+HookObject_rbp]
	
	mov rsi, [rcx+HookObject_ReturnAddress]
	mov [rsp], rsi
	
	mov rsi, [rcx+HookObject_rsi]
	mov rax, [rcx+HookObject_rax]
	ret
HookRoutine endp


end
