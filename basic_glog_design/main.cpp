#include <iostream>
#include "base_log.h"

using std::cout;
using std::endl;

int main(int argc, const char** argv) {
  int a = 0;
  int b = 2;

  InitInvocationName(argv[0]);

  LOG(INFO) << "234jklrjksldjfsdl" << endl ;
  LOG(ERROR) << "asdfalskdfjweorjewo" << "\n";

  return 0;
}
