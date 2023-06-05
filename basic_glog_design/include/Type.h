#ifndef _TYPE_H_
#define _TYPE_H_

#include <iostream>
#include <string.h>

using LogSeverity = int;

typedef std::int32_t int32;
typedef std::uint32_t uint32;
typedef std::int64_t int64;
typedef std::uint64_t uint64;

typedef double WallTime;

const int GLOG_INFO = 0, GLOG_WARNING = 1, GLOG_ERROR = 2, GLOG_FATAL = 3,
  NUM_SEVERITIES = 4;

const char* const LogSeverityNames[NUM_SEVERITIES] = {
  "INFO", "WARNING", "ERROR", "FATAL"
};

static const char* g_program_invocation_short_name = nullptr;

static bool BoolFromEnv(const char* varname, bool defval) {
    const char* const valstr = getenv(varname);
    if (!valstr) {
        return defval;
    }
    return memchr("tTyY1\0", valstr[0], 6) != nullptr;
}

enum GLogColor {
    COLOR_DEFAULT,
    COLOR_RED,
    COLOR_GREEN,
    COLOR_YELLOW
};



#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
#define OS_WINDOWS
#elif defined(__CYGWIN__) || defined(__CYGWIN32__)
#define OS_CYGWIN
#elif defined(linux) || defined(__linux) || defined(__linux__)
#ifndef OS_LINUX
#define OS_LINUX
#endif
#elif defined(macintosh) || defined(__APPLE__) || defined(__APPLE_CC__)
#define OS_MACOSX
#elif defined(__FreeBSD__)
#define OS_FREEBSD
#elif defined(__NetBSD__)
#define OS_NETBSD
#elif defined(__OpenBSD__)
#define OS_OPENBSD
#elif defined(__EMSCRIPTEN__)
#define OS_EMSCRIPTEN
#else
// TODO(hamaji): Add other platforms.
#error Platform not supported by glog. Please consider to contribute platform information by submitting a pull request on Github.
#endif


#define DECLARE_VARIABLE(type, shorttype, name, tn) \
  namespace fL##shorttype {                         \
    extern type FLAGS_##name;           \
  }                                                 \
  using fL##shorttype::FLAGS_##name
#define DEFINE_VARIABLE(type, shorttype, name, value, meaning, tn) \
  namespace fL##shorttype {                                        \
    type FLAGS_##name(value);                          \
    char FLAGS_no##name;                                           \
  }                                                                \
  using fL##shorttype::FLAGS_##name

#define DEFINE_string(name, value, meaning)                   \
  namespace fLS {                                             \
  std::string FLAGS_##name##_buf(value);                      \
  std::string& FLAGS_##name = FLAGS_##name##_buf; \
  char FLAGS_no##name;                                        \
  }                                                           \
  using fLS::FLAGS_##name

// bool specialization
#define DECLARE_bool(name) \
  DECLARE_VARIABLE(bool, B, name, bool)
#define DEFINE_bool(name, value, meaning) \
  DEFINE_VARIABLE(bool, B, name, value, meaning, bool)

#define EnvToBool(envname, dflt) \
  (!getenv(envname) ? (dflt)     \
                    : memchr("tTyY1\0", getenv(envname)[0], 6) != nullptr)

#define EnvToInt(envname, dflt) \
  (!getenv(envname) ? (dflt) : strtol(getenv(envname), nullptr, 10))

#define EnvToString(envname, dflt) \
    (!getenv(envname) ? (dflt) : getenv(envname))

#define EnvToUInt(envname, dflt) \
    (!getenv(envname) ? (dflt) : strtoul(getenv(envname), nullptr, 10))
// int32 specialization
#define DECLARE_int32(name) \
  DECLARE_VARIABLE(int32, I, name, int32)
#define DEFINE_int32(name, value, meaning) \
  DEFINE_VARIABLE(int32, I, name, value, meaning, int32)


#define GLOG_DEFINE_bool(name, value, meaning) \
  DEFINE_bool(name, EnvToBool("GLOG_" #name, value), meaning)

#define GLOG_DEFINE_int32(name, value, meaning) \
  DEFINE_int32(name, EnvToInt("GLOG_" #name, value), meaning)

#define GLOG_DEFINE_string(name, value, meaning)  \
    DEFINE_string(name, EnvToString("GLOG_" #name, value), meaning)

// uint32 specialization
#ifndef DECLARE_uint32
#define DECLARE_uint32(name) \
  DECLARE_VARIABLE(uint32, U, name, uint32)
#endif // DECLARE_uint64
#define DEFINE_uint32(name, value, meaning) \
  DEFINE_VARIABLE(uint32, U, name, value, meaning, uint32)

#define GLOG_DEFINE_uint32(name, value, meaning) \
  DEFINE_uint32(name, EnvToUInt("GLOG_" #name, value), meaning)


pid_t GetTID();

#endif
