#pragma once

#include <string>

void writeFile( const std::string& name, const std::string& content );
std::string readFile( const std::string& name );

std::string writeBackFile( const std::string& serial, const std::string& cert, const std::string& keydir );
