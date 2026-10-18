#include <algorithm>
#include <exception>
#include <iostream>
#include <locale>
#include <stdexcept>
#include <string>
#include <vector>

int main(int argc, char **argv) {
    try {
        std::vector<std::string> values{"reference", argc > 1 ? argv[1] : "installed-runtime"};
        std::sort(values.begin(), values.end());
        std::locale locale("C");
        if (values.front().empty()) throw std::runtime_error("empty reference");
        std::cout.imbue(locale);
        std::cout << values.back() << ':' << values.front().size();
        return 0;
    } catch (const std::exception &error) {
        return error.what()[0] == '\0';
    }
}
