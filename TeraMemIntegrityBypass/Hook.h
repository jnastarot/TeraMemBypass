#pragma once

#ifdef _WIN64
#include "HDE\hde64.h"
#else
#include "HDE\hde32.h"
#endif

typedef struct _HDEHook {
	int lenSaveCode;
	BYTE * src;
	BYTE trampline[50];
	bool init;
	_HDEHook() {
		lenSaveCode = 0;
		src = 0;
		init = false;
		ZeroMemory(trampline, sizeof(trampline));
	}
}HDEHook, *pHDEHook;


void *DetourCreate(BYTE *src, const BYTE *dst, const int len)
{
	BYTE *jmp;
	DWORD dwback;
	DWORD jumpto, newjump;

	VirtualProtect(src, len, PAGE_READWRITE, &dwback);

	if (src[0] == 0xE9)
	{
		jmp = (BYTE*)malloc(10);
		jumpto = (*(DWORD*)(src + 1)) + ((DWORD)src) + 5;
		newjump = (jumpto - (DWORD)(jmp + 5));
		jmp[0] = 0xE9;
		*(DWORD*)(jmp + 1) = newjump;
		jmp += 5;
		jmp[0] = 0xE9;
		*(DWORD*)(jmp + 1) = (DWORD)(src - jmp);
	}
	else
	{
		jmp = (BYTE*)malloc(5 + len);
		memcpy(jmp, src, len);
		jmp += len;
		jmp[0] = 0xE9;
		*(DWORD*)(jmp + 1) = (DWORD)(src + len - jmp) - 5;
	}
	src[0] = 0xE9;
	*(DWORD*)(src + 1) = (DWORD)(dst - src) - 5;

	for (int i = 5; i < len; i++)
		src[i] = 0x90;
	VirtualProtect(src, len, dwback, &dwback);
	return (jmp - len);
}

#ifdef _WIN64
int GetLenFromBytesCode(BYTE* Address, int NeededLen)
{
	int Len = 0;
	while (Len < NeededLen)
	{
		hde64s Comhde;
		hde64_disasm(&Address[Len], &Comhde);
		Len += Comhde.len;
	}
	return Len;
}
#else
int GetLenFromBytesCode(BYTE* Address, int NeededLen)
{
	int Len = 0;
	while (Len < NeededLen)
	{
		hde32s Comhde;
		hde32_disasm(&Address[Len], &Comhde);
		Len += Comhde.len;
	}
	return Len;
}
#endif


void CreateHook(BYTE *src, const BYTE *dst, pHDEHook hook)
{
	DWORD dwback, dwback1;
again:
	if (src[0] == 0xE9) {
		src = *(DWORD*)&src[1] + 5 + src;
		goto again;
	}

	hook->src = src;
	hook->lenSaveCode = GetLenFromBytesCode(src, 5);
	VirtualProtect(src, 100, PAGE_EXECUTE_READWRITE, &dwback1);
	memcpy(&hook->trampline[0], src, hook->lenSaveCode);
	hook->trampline[hook->lenSaveCode] = 0xE9;
	*(DWORD*)&hook->trampline[hook->lenSaveCode + 1] = (DWORD)src + hook->lenSaveCode - (DWORD)&hook->trampline[hook->lenSaveCode] - 5;
	VirtualProtect(hook->trampline, hook->lenSaveCode + 5, PAGE_EXECUTE_READWRITE, &dwback);
	DetourCreate(src, dst, 5);
	VirtualProtect(src, 100, dwback1, &dwback1);
	hook->init = true;
}

void CreateUnHook(pHDEHook hook) {
	if (hook->init) {
		DWORD dwback;
		VirtualProtect(hook->src, 100, PAGE_EXECUTE_READWRITE, &dwback);
		memcpy(hook->src, hook->trampline, hook->lenSaveCode);
		VirtualProtect(hook->src, 100, dwback, &dwback);
	}
}