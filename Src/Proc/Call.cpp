#include "..\Pe\Pe.h"

void Process::Encode_value(std::vector<BYTE>& shellcode, UINT32 val)
{
	BYTE* val_ptr = (BYTE*)&val;
	for (size_t i = 0; i < sizeof(UINT32); i++)
	{
		shellcode.push_back(val_ptr[i]);
	}
}
void Process::Encode_value(std::vector<BYTE>& shellcode, UINT64 val)
{
	BYTE* val_ptr = (BYTE*)&val;
	for (size_t i = 0; i < sizeof(UINT64); i++)
	{
		shellcode.push_back(val_ptr[i]);
	}
}

void Process::Create_push64(std::vector<BYTE>& shellcode, UINT64 val)
{
	shellcode.push_back(0x48); shellcode.push_back(0xb8); //movabs rax,
	Encode_value(shellcode, val);
	shellcode.push_back(0x50);//push rax
}

void Process::Create_push32(std::vector<BYTE>& shellcode, UINT32 val)
{
	shellcode.push_back(0x68); //push
	Encode_value(shellcode, val);
}

void Process::Create_call(std::vector<BYTE>& shellcode, UINT64 addr)
{
	if (is_32_bit)
	{
		shellcode.push_back(0xb8);//mov eax
		Encode_value(shellcode, (UINT32)addr);
		shellcode.push_back(0xFF); shellcode.push_back(0xd0);//call rax/eax
	}
	else
	{
		shellcode.push_back(0x55);//push rbp (save rbp)
		shellcode.push_back(0x48); shellcode.push_back(0x83); shellcode.push_back(0xec); shellcode.push_back(0x20); //sub rsp, 0x20 (allocate save space for volatile registers)
		shellcode.push_back(0x48); shellcode.push_back(0x8d); shellcode.push_back(0x2c); shellcode.push_back(0x24);	//lea rbp, [rsp] (set rbp)


		shellcode.push_back(0x48); shellcode.push_back(0xb8);//mov rax
		Encode_value(shellcode, (UINT64)addr);
		shellcode.push_back(0xFF); shellcode.push_back(0xd0);//call rax/eax
		shellcode.push_back(0x48); shellcode.push_back(0x83); shellcode.push_back(0xc4); shellcode.push_back(0x20); //add    rsp,0x20
		shellcode.push_back(0x5d);// pop    rbp
	}
}