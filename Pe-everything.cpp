#include "Pe.h"

//todo
/*
	rework import/export_info layout
	fix driver relocs
	out of bounds checks for read

	deep scan function (only code ignore data and follow complete control flow)
*/

int main()
{
	Pe steam{"", "steam.exe"};
	if (!steam.Success())
	{
		printf("Failed to init steam %X, comment %s\n", steam.Get_error(), steam.Get_error_comment()->c_str());
		return 1;
	}

	Pe dll("C:\\Users\\sentient\\Documents\\GitHub\\Vac3SteamBypass\\Release\\Vac3SteamBypass.dll");
	if (!dll.Success())
	{
		printf("Failed to init dll %X, comment %s\n", dll.Get_error(), dll.Get_error_comment()->c_str());
		return 1;
	}

	return 0;
}

