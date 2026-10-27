#include "../app/src/main/cpp/core.hpp"
#include <cassert>
int main() {
    assert(sql_lines("cursor.execute(\"SELECT \" + input)").size()==1);
    assert(sql_lines("cursor.execute(\"SELECT ?\", (input,))").empty());
    assert(sql_lines("text\nrawQuery(\"SELECT \" + input)")[0]==2);
    assert(sql_lines("").empty());
}
