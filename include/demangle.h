#ifndef BASE_DEMANGLE_H_
#define BASE_DEMANGLE_H_

#include "config.h"
#include <glog/logging.h>

_START_GOOGLE_NAMESPACE_

// Demangle "mangled". On Success, return true and write the 
// demangled symbol name to "out". Otherwise, return false.
// "out" is modified even if demangling is unsuccessful
bool GLOG_EXPORT Demangle(const char* mangled, char* out, size_t out_size);

_END_GOOGLE_NAMESPACE_



#endif
