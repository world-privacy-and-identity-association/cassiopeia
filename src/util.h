#pragma once

#include <string>
#include <ctime>
#include <memory>

void writeFile( const std::string& name, const std::string& content );
std::string readFile( const std::string& name );

std::string writeBackFile( const std::string& serial, const std::string& cert, const std::string& keydir );

std::pair<bool, std::time_t> parseDate( const std::string& date );
std::pair<bool, std::time_t> parseMonthInterval( std::time_t t, const std::string& date );
std::pair<bool, std::time_t> parseYearInterval( std::time_t t, const std::string& date );

std::shared_ptr<std::ofstream> openLogfile( const std::string name );
