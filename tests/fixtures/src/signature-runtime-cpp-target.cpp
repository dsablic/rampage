#include <algorithm>
#include <exception>
#include <iostream>
#include <locale>
#include <stdexcept>
#include <string>
#include <vector>

int main(int argc, char **argv) {
    try {
        std::vector<std::string> values{"target-distinct", argc > 1 ? argv[1] : "runtime"};
        std::reverse(values.begin(), values.end());
        std::locale locale("C");
        if (values.back().empty()) throw std::length_error("empty target");
        std::cerr.imbue(locale);
        std::cerr << values.front().size() << ':' << values.back();
        return 0;
    } catch (const std::exception &error) {
        return error.what()[0] == '\0';
    }
}
