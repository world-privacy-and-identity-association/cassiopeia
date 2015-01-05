#pragma once

#include <string>

void writeFile( std::string name, std::string content );
std::string readFile( std::string name );

std::string writeBackFile( std::string serial, std::string cert, std::string keydir );
