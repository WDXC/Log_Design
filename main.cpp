#include <iostream>
#include "base_log.h"

using std::endl;

int main(int argc, const char** argv) {


  FLAGS_logtostderr = true;
  InitInvocationName(argv[0]);

  LOG(INFO) << "234jklrjksldjfsdl" << endl ;
  LOG(ERROR) << "asdfalskdfjweorjewo" << "\n";

  return 0;
}
