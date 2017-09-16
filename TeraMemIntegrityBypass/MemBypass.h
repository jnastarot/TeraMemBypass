#pragma once


DWORD MemCheck_1;// = 0x027A3B89;
DWORD MemCheck_2;// = 0x0262EC78;

HDEHook Bypass;

DWORD RetjmpBypass = (DWORD)&Bypass.trampline[0] + 2;
BYTE membypass[10] = { 0 };
DWORD nBytes;

DWORD WINAPI CmpAddress(DWORD Address)
{
	if ((Address <= MemCheck_1 && Address >= MemCheck_1 - 3) || (Address >= MemCheck_1 && Address <= MemCheck_1 + 3))
	{
		DWORD Offset = Address - MemCheck_1;
		if (Offset < 0)
		{
			nBytes = *(DWORD*)&membypass[3 - Offset];
		}
		else
		{
			nBytes = *(DWORD*)&membypass[3 + Offset];
		}
		return 1;
	}
	return 0;
}


BYTE pushdinamicreg[15] = { 0 };
BYTE movdinreg[15] = { 0 };
BYTE movfakereg[15] = { 0 };

DWORD Apushdinamicreg = (DWORD)&pushdinamicreg[0];
DWORD Amovdinreg = (DWORD)&movdinreg[0];
DWORD Amovfakereg = (DWORD)&movfakereg[0];
DWORD ACmpAddress = (DWORD)&CmpAddress;

void WINAPI GetRegistr()
{
	BYTE reg = Bypass.trampline[1];
	reg = reg % 8;

	//mov reg,[reg]
	movdinreg[0] = Bypass.trampline[0];
	movdinreg[1] = Bypass.trampline[1];
	movdinreg[2] = 0xC3;

	//push reg
	pushdinamicreg[0] = reg + 0x50;
	pushdinamicreg[1] = 0xFF;
	pushdinamicreg[2] = 0x15;
	*(DWORD*)&pushdinamicreg[3] = (DWORD)&ACmpAddress;
	pushdinamicreg[7] = 0xC3;


	if (reg == 0)//eax
	{
		movfakereg[0] = 0xA1;
		*(DWORD*)&movfakereg[1] = (DWORD)&nBytes;
		movfakereg[5] = 0xC3;
	}
	else
	{
		movfakereg[0] = 0x8B;
		movfakereg[1] = 0x0D + (reg - 1) * 8;
		*(DWORD*)&movfakereg[2] = (DWORD)&nBytes;
		movfakereg[6] = 0xC3;
	}

}
bool Tested = 0;

__declspec(naked)void BypassHandler()
{
	_asm
	{
		pushf
		pushad
		cmp Tested, 1
		je istested
		call GetRegistr
		mov Tested, 1
		istested :

		call[Apushdinamicreg]

			//	push esi
			//	call CmpAddress

			cmp eax, 1

			jne usualend
			popad
			popf


			call[Amovfakereg]

			//mov esi, dword ptr [nBytes]
			jmp dword ptr[RetjmpBypass]

			usualend :
		popad
			popf

			call[Amovdinreg]
			//mov esi, [esi]
			jmp dword ptr[RetjmpBypass]
	}
}



void TeraBypass()
{
	memcpy(membypass, (void*)(MemCheck_1 - 3), 8);
	CreateHook((LPBYTE)MemCheck_2, (LPBYTE)BypassHandler, &Bypass);
	*(WORD*)MemCheck_1 = 0xC039;
}

void TeraUnBypass() {
	*(WORD*)MemCheck_1 = 0xC039;
	CreateUnHook(&Bypass);
}