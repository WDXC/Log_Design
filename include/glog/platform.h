#ifndef GLOG_PLATFORM_H
#define GLOG_PLATFORM_H

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
#define GLOG_OS_WINDOWS
#elif defined(__CYGWIN__) || defined(__CYGWIN32__)
#define GLOG_OS_CYGWIN
#elif defined(linux) || defined(__linux) || defined(__linux__)
#ifndef GLOG_OS_LINUX
#define GLOG_OS_LINUX
#endif
#elif defined(macintosh) || defined(__APPLE__) || defined(__APPLE_CC__)
#define GLOG_OS_MACOSX
#elif defined(__FreeBSD__)
#define GLOG_OS_FREEBSD
#elif defined(__NetBSD__)
#define GLOG_OS_NETBSD
#elif defined(__OpenBSD__)
#define GLOG_OS_OPENBSD
#elif defined(__EMSCRIPTEN__)
#define GLOG_OS_EMSCRIPTEN
#else
// TODO(hamaji): Add other platforms.
#error Platform not supported by glog. Please consider to contribute platform information by submitting a pull request on Github.
#endif

#endif // GLOG_PLATFORM_H
