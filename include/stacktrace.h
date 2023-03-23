#ifndef BASE_STACKTRACE_H_
#define BASE_STACKTRACE_H_

#include "config.h"
#include <glog/logging.h>

_START_GOOGLE_NAMESPACE_

GLOG_EXPORT int GetStackTrace(void** result, int max_depth, int skip_count);

_END_GOOGLE_NAMESPACE_

#endif
