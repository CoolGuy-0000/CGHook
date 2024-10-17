#include <Windows.h>
#include "CGhook.h"
#include "distorm/distorm.h"

using namespace CGHOOK;

extern CRITICAL_SECTION g_CritSection;

extern "C" void* __hook_segment_address;
extern "C" size_t __hook_segment_size;
extern "C" size_t __hook_routine_offs;

static char hook_shell_code_64[] = {
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFF, 0x20
};

static char hook_shell_code_64_2[] = {
	0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

extern "C" void CGUnHook(HookObject* obj) {
	DWORD oldProtect;
	EnterCriticalSection(&g_CritSection);

	VirtualProtect(obj->OriginalAddress, obj->BackupSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(obj->OriginalAddress, obj->BackupCode, obj->BackupSize);
	VirtualProtect(obj->OriginalAddress, obj->BackupSize, oldProtect, &oldProtect);

	VirtualProtect(obj, __hook_segment_size, obj->mem_type, &oldProtect);
	free(obj);

	LeaveCriticalSection(&g_CritSection);
}

extern "C" HookObject* CGHook(void* target, WORD id, WORD max_callbacks, bool post, bool ignore) {

	size_t CallBacksSize = (sizeof(void*) * max_callbacks);

	HookObject* temp = (HookObject*)malloc(__hook_segment_size + CallBacksSize);

	if (temp) {
		EnterCriticalSection(&g_CritSection);

		DWORD oldProtect;
		VirtualProtect(temp, __hook_segment_size, PAGE_EXECUTE_READWRITE, &oldProtect);
		
		*(size_t*)((size_t)hook_shell_code_64 + 2) = (size_t)temp;

		memcpy(temp, __hook_segment_address, __hook_segment_size);

		temp->HookRoutine = (void*)((size_t)temp + __hook_routine_offs);
		temp->OriginalAddress = target;
		temp->Id = id;
		temp->Flags |= post ? CGHOOK_FLAG_POST : 0;
		temp->Flags |= ignore ? CGHOOK_FLAG_IGNORE : 0;
		temp->MaxCallBacks = max_callbacks;
		temp->BackupSize = 0;
		temp->CallBacks = (void**)((size_t)temp + __hook_segment_size);
		temp->mem_type = oldProtect;

		_CodeInfo ci;
		_DInst* inst = (_DInst*)malloc(sizeof(_DInst) * 20);
		UINT instruction_count;

		ci.code = (BYTE*)target;
		ci.codeLen = 0x1000;
		ci.codeOffset = 0;
		ci.addrMask = -1;
		ci.dt = Decode64Bits;
		ci.features = DF_USE_ADDR_MASK;

		distorm_decompose64(&ci, inst, 20, &instruction_count);

		for (size_t i = 0; i < instruction_count; i++) {
			if (temp->BackupSize >= sizeof(hook_shell_code_64))break;
			temp->BackupSize += inst[i].size;
		}

		free(inst);

		temp->ReturnAddress = (void*)((size_t)target + temp->BackupSize);
		*(size_t*)((size_t)hook_shell_code_64_2 + 6) = (size_t)temp->ReturnAddress;

		VirtualProtect(target, temp->BackupSize, PAGE_EXECUTE_READWRITE, &oldProtect);

		memcpy(temp->BackupCode, target, temp->BackupSize);
		memcpy((void*)((size_t)temp->BackupCode + temp->BackupSize), hook_shell_code_64_2, sizeof(hook_shell_code_64_2));

		memcpy(target, hook_shell_code_64, sizeof(hook_shell_code_64));

		long long int blank = temp->BackupSize - sizeof(hook_shell_code_64);

		if (blank > 0)
			memset((void*)((size_t)target + sizeof(hook_shell_code_64)), 0x90, blank);

		VirtualProtect(target, temp->BackupSize, oldProtect, &oldProtect);

		LeaveCriticalSection(&g_CritSection);
		return temp;
	}

	return NULL;
}