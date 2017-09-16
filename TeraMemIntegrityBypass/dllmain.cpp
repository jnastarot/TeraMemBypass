#include <Windows.h>
#include "Hook.h"
#include "MemBypass.h"


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH: {
		MemCheck_1 = 0x02DF54AE;
		MemCheck_2 = 0x02BF33EC;
		TeraBypass();
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH: {
		TeraUnBypass();
		break;
	}

	}
	return TRUE;
}

