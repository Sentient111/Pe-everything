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
	Error_struct error = { 0 };

	Pe steam{&error, "", "steam.exe"};
	if (!error.Success())
	{
		printf("Failed to init steam %X, comment %s\n", error.last_err, error.error_comment.c_str());
		return 1;
	}

	Pe dll(&error, "C:\\Users\\sentient\\Documents\\GitHub\\Vac3SteamBypass\\Release\\Vac3SteamBypass.dll");
	if (!error.Success())
	{
		printf("Failed to init dll %X, comment %s\n", error.last_err, error.error_comment.c_str());
		return 1;
	}

	return 0;
}

