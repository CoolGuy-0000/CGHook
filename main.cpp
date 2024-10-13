#include <Windows.h>

CRITICAL_SECTION g_CritSection;



BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		InitializeCriticalSection(&g_CritSection);
		DisableThreadLibraryCalls(hinstDLL);
	}
	else if (fdwReason == DLL_PROCESS_DETACH) {
		DeleteCriticalSection(&g_CritSection);
	}
	

	return TRUE;
}