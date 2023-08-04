#include "Pe.h"

bool Nt::Set_os_platform(UINT64 nt_addr)
{
	RESET_ERR();

	WORD* platform = (WORD*)pe->Read(nt_addr + offsetof(IMAGE_NT_HEADERS, FileHeader) + sizeof(IMAGE_FILE_HEADER), sizeof(WORD));
	if (!platform)
		return false;

	if (*platform == 0x10b)//PE32
		is_32_bit = true;
	else if (*platform == 0x20b)//PE32+
		is_32_bit = false;
	else
	{
		last_err = ERROR_INVALID_EXE_SIGNATURE;
		error_comment = CREATE_ERROR("os platform has invalid value %X\n", platform);
		return false;
	}
	return true;
}

#define IMAGE_FILE_MACHINE_LOONGARCH32 0x6232
#define IMAGE_FILE_MACHINE_LOONGARCH64 0x6264
#define IMAGE_FILE_MACHINE_RISCV32 0x5032
#define IMAGE_FILE_MACHINE_RISCV64 0x5064
#define IMAGE_FILE_MACHINE_RISCV128 0x5128

Execution_enviornment Nt::Get_execution_enviornment()
{
	RESET_ERR();

	WORD machine = 0;
	if (is_32_bit)
		machine = nt_32_headers->FileHeader.Machine;
	else
		machine = nt_64_headers->FileHeader.Machine;

	switch (machine)
	{
		case IMAGE_FILE_MACHINE_UNKNOWN:
			return Execution_enviornment::unknown;
		case IMAGE_FILE_MACHINE_ALPHA:
			return Execution_enviornment::Alpha_AXP32;
		case IMAGE_FILE_MACHINE_ALPHA64:
			return Execution_enviornment::Alpha_64;
		case IMAGE_FILE_MACHINE_AM33:
			return Execution_enviornment::Matsushita_AM33;
		case IMAGE_FILE_MACHINE_AMD64:
			return Execution_enviornment::x64;
		case IMAGE_FILE_MACHINE_ARM:
			return Execution_enviornment::ARM_little_endian;
		case IMAGE_FILE_MACHINE_ARM64:
			return Execution_enviornment::ARM64_little_endian;
		case IMAGE_FILE_MACHINE_ARMNT:
			return Execution_enviornment::ARM_Thumb_2_little_endian;
		case IMAGE_FILE_MACHINE_EBC:
			return Execution_enviornment::EFI_byte_code;
		case IMAGE_FILE_MACHINE_I386:
			return Execution_enviornment::Intel_386;
		case IMAGE_FILE_MACHINE_IA64:
			return Execution_enviornment::Intel_Itanium_processor_family;
		case IMAGE_FILE_MACHINE_LOONGARCH32:
			return Execution_enviornment::LoongArch_32_bit;
		case IMAGE_FILE_MACHINE_LOONGARCH64:
			return Execution_enviornment::LoongArch_64_bit;
		case IMAGE_FILE_MACHINE_M32R:
			return Execution_enviornment::Mitsubishi_M32R_little_endian;
		case IMAGE_FILE_MACHINE_MIPS16:
			return Execution_enviornment::MIPS16;
		case IMAGE_FILE_MACHINE_MIPSFPU:
			return Execution_enviornment::MIPS_with_FPU;
		case IMAGE_FILE_MACHINE_MIPSFPU16:
			return Execution_enviornment::MIPS16_with_FPU;
		case IMAGE_FILE_MACHINE_POWERPC:
			return Execution_enviornment::Power_PC_little_endian;
		case IMAGE_FILE_MACHINE_POWERPCFP:
			return Execution_enviornment::Power_PC_with_floating_point_support;
		case IMAGE_FILE_MACHINE_R4000:
			return Execution_enviornment::MIPS_little_endian;
		case IMAGE_FILE_MACHINE_RISCV32:
			return Execution_enviornment::RISCV_32;
		case IMAGE_FILE_MACHINE_RISCV64:
			return Execution_enviornment::RISCV_64;
		case IMAGE_FILE_MACHINE_RISCV128:
			return Execution_enviornment::RISCV_128;
		case IMAGE_FILE_MACHINE_SH3:
			return Execution_enviornment::Hitachi_SH3;
		case IMAGE_FILE_MACHINE_SH3DSP:
			return Execution_enviornment::Hitachi_SH3_DSP;
		case IMAGE_FILE_MACHINE_SH4:
			return Execution_enviornment::Hitachi_SH4;
		case IMAGE_FILE_MACHINE_SH5:
			return Execution_enviornment::Hitachi_SH5;
		case IMAGE_FILE_MACHINE_THUMB:
			return Execution_enviornment::Thumb;
		case IMAGE_FILE_MACHINE_WCEMIPSV2:
			return Execution_enviornment::MIPS_little_endian_WCE_v2;

		default:
		{
			last_err = ERROR_INVALID_CATEGORY;
			error_comment = CREATE_ERROR("Invalid machine type %X\n", machine);
			return Execution_enviornment::invalid;
		}
	}
}

bool Nt::Has_characteristics(DWORD flag)
{
	if (is_32_bit)
		return nt_32_headers->FileHeader.Characteristics & flag;
	else
		return nt_64_headers->FileHeader.Characteristics & flag;
}

Subsystem_target Nt::Get_subsystem_target()
{
	RESET_ERR();

	WORD subsystem = 0;
	if (is_32_bit)
		subsystem = nt_32_headers->OptionalHeader.Subsystem;
	else
		subsystem = nt_64_headers->OptionalHeader.Subsystem;

	switch (subsystem)
	{
		case IMAGE_SUBSYSTEM_UNKNOWN:
			return Subsystem_target::unknown;
		case IMAGE_SUBSYSTEM_NATIVE:
			return Subsystem_target::native;
		case IMAGE_SUBSYSTEM_WINDOWS_GUI:
			return Subsystem_target::gui;
		case IMAGE_SUBSYSTEM_WINDOWS_CUI:
			return Subsystem_target::character;
		case IMAGE_SUBSYSTEM_OS2_CUI:
			return Subsystem_target::os2_character;
		case IMAGE_SUBSYSTEM_POSIX_CUI:
			return Subsystem_target::posix_character;
		case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
			return Subsystem_target::native_win9;
		case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
			return Subsystem_target::ce_gui;
		case IMAGE_SUBSYSTEM_EFI_APPLICATION:
			return Subsystem_target::efi;
		case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER :
			return Subsystem_target::boot_efi;
		case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
			return Subsystem_target::runtime_efi;
		case IMAGE_SUBSYSTEM_EFI_ROM:
			return Subsystem_target::rom_efi;
		case IMAGE_SUBSYSTEM_XBOX:
			return Subsystem_target::xbox;
		case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
			return Subsystem_target::boot;

		default:
		{
			last_err = ERROR_INVALID_CATEGORY;
			error_comment = CREATE_ERROR("invalid subsystem %X\n", subsystem);
			return Subsystem_target::invalid;
		}
	}
}