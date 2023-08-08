#pragma once
#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <string>
#include <fstream>

#include <tlhelp32.h>
#include <psapi.h>


#define INVALID_HANDLE(x) !x || x == INVALID_HANDLE_VALUE


template<typename ... Args>
std::string Format_string(const std::string& format, Args ... args)
{
	int size_s = std::snprintf(nullptr, 0, format.c_str(), args ...) + 1; //null term

	if (!size_s)
		return "";

	std::unique_ptr<char[]> buf(new char[size_s]);
	std::snprintf(buf.get(), size_s, format.c_str(), args ...);
	return std::string(buf.get(), buf.get() + size_s - 1); //remove null term
}

template <typename Char_type = char>
bool Str_cmp(Char_type* str1, Char_type* str2)
{
	for (size_t i = 0; i < MAX_PATH +1 ; i++)
	{
		if (str1[i] == 0 || str2[i] == 0)
			return true;

		if (std::tolower((int)str1[i]) != std::tolower((int)str2[i]))
			return false;
	}
	return true;
}


// '/' for linux
#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__) //removes the whole path from __file__ so only the filename shows up

//Adds filename and line where error occoured
#define CREATE_ERROR(fmt, ...) std::string("[PE] Error in ") + __FILENAME__ + " on line " + std::to_string(__LINE__) + " " + Format_string(fmt, ##__VA_ARGS__); 

//just prints the result of the CREATE_ERROR might be good to replace in a somewhat release enviornment
#define PRINT_ERROR(fmt, ...) printf("[PE] Error in %s on line %i\ncomment: ", __FILENAME__, __LINE__); printf(fmt, ##__VA_ARGS__);


