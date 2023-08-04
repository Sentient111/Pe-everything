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
	Pe myPe{}; //"win32k.sys", "", true
	if (!myPe.Success())
	{
		printf("Failed to init my pe %X, comment %s\n", myPe.Get_error(), myPe.Get_error_comment()->c_str());
		return 1;
	}

	Nt* nt_data = myPe.Get_nt();
	if (!nt_data->Success())
		return 0;


	Import_info imports = { 0 };
	nt_data->Get_import_dir(&imports);
	if (!nt_data->Success())
		return 0;

	Export_info exports = { 0 };
	nt_data->Get_export_dir(&exports);
	if (!nt_data->Success())
		return 0;

	if (!nt_data->Is_missing_relocs())
	{
		Reloc_info relocs = { 0 };
		nt_data->Get_reloc_dir(&relocs); //fucked for drivers
		if (!nt_data->Success())
			return 0;
	}

	return 0;
}

