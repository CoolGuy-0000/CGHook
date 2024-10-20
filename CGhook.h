#ifndef CG_HOOK_H
#define CG_HOOK_H

#include <Windows.h>

#define CGHOOK_VERSION 1

#define CGHOOK_FLAG_POST (1 << 0)
#define CGHOOK_FLAG_IGNORE (1 << 1)

namespace CGHOOK {

	typedef struct {
		void* HookRoutine;

		size_t rsp;
		size_t rbp;
		size_t rax;

		size_t rcx;
		size_t rdx;
		size_t r8;
		size_t r9;

		void* OriginalAddress;
		void* ReturnAddress;

		WORD Id;
		WORD Flags;
		WORD BackupSize;
		WORD MaxCallBacks;

		BYTE BackupCode[0x30];

		void** CallBacks;

		size_t mem_type;

	} HookObject;
	
}

extern "C" {
	#ifndef CG_BUILD
	__declspec(dllimport) void CGUnHook(CGHOOK::HookObject* obj);
	__declspec(dllimport) CGHOOK::HookObject* CGHook(void* target, WORD id, WORD max_callbacks, bool post = false, bool ignore = false);
	#else
	__declspec(dllexport) void CGUnHook(CGHOOK::HookObject* obj);
	__declspec(dllexport) CGHOOK::HookObject* CGHook(void* target, WORD id, WORD max_callbacks, bool post = false, bool ignore = false);
	#endif
};

#endif