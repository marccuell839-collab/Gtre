#pragma once
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cctype>
inline std::vector<int> sql_lines(const std::string& source) {
    std::vector<int> result;
    std::istringstream input(source);
    std::string line;
    int number = 0;
    while (std::getline(input, line)) {
        ++number;
        std::transform(line.begin(), line.end(), line.begin(), [](unsigned char c){ return std::tolower(c); });
        bool sink = line.find("execute(") != std::string::npos || line.find("rawquery(") != std::string::npos || line.find("execsql(") != std::string::npos;
        bool dynamic = line.find('+') != std::string::npos || line.find(".format(") != std::string::npos || line.find("f\"") != std::string::npos || line.find("f'") != std::string::npos;
        if (sink && dynamic) result.push_back(number);
    }
    return result;
}
