#include "Common.h"

#include <fstream>
#include <cassert>
#include <iostream>

static std::unique_ptr<std::fstream> file;
std::string SolutionDir = "../../";

void InitDebugPrinting(std::string filePath)
{
	std::cout << "changing sink" << std::endl;

	if (file == nullptr)
	{
		file.reset(new std::fstream);
	}
	else
	{
		file->close();
	}

	file->open(filePath, std::ios::trunc | std::ofstream::out);

	if (!file->is_open())
		throw UnitTestFail();

	//time_t now = time(0);

	std::cout.rdbuf(file->rdbuf());
	std::cerr.rdbuf(file->rdbuf());
	//Log::SetSink(*file);
}

