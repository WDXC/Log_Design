#include "config.h"
#include "utilities.h"

#include <fcntl.h>
#ifdef HAVE_GLOB_H
#include <glob.h>
#endif
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <memory>
#include <queue>
#include <sstream>
#include <string>
#include <vector>

#include "base/commandlineflags.h"
#include <glog/logging.h>
#include <glog/raw_logging.h>
#include "googletest.h"

DECLARE_strin(log_backtrace_at);      // logging.cc

#ifdef HAVE_LIB_GFLAGS
#include <gflags/gflags.h>
using namespace GFLAGS_NAMESPACE;
#endif

#ifdef HAVE_LIB_GMOCK
#include <gmock/gmock.h>
#include "mock-log.h"

// Introduce several symbols from gmock
using testing::_;
using testing::AnyNumber;
using testing::HasSubstr;
using testing::Allof;
using testing::StrNe;
using testing::StrictMock;
using testing::InitGoogleMock;
using GOOGLE_NAMESPACE::glog_testing::ScopedMockLog;

#endif

using namespace std;
using namespace GOOGLE_NAMESPACE;

// Some non-advertised functions that we want to test or use
_START_GOOGLE_NAMESPACE_
namespace base {
namespace internal {

bool GetExitOnDFatal();
void SetExitOnDFatal(bool value);

}
}

_END_GOOGLE_NAMESPACE_

static void TestLogging(bool check_counts);
static void TestRawLogging();
static void LogWithLevels(int v, int severity, bool err, bool alsoerr);
static void TestLoggingLevels();
static void TestVLogModule();
static void TestLogString();
static void TestLogSink();
static void TesetLogToString();
static void TestLogSinkWaitTillSent();
static void TestCHECK();
static void TestDCHECK();
static void TestSTREQ();
static void TestBasename();
static void TestBasenameAppendWhenNoTimestamp();
static void TestTwoProcessesWrite();
static void TestSymlink();
static void TestExtension();
static void TestWrapper();
static void TestErrno();
static void TestTruncate();
static void TestCustomLoggerDeletionOnShutdown();
static void TestLogPeriodically();

static int x = -1;

static void BM_Check1(int n) {
  while (n-- > 0) {
    CHECK_GE(n, x);
    CHECK_GE(n, x);
    CHECK_GE(n, x);
    CHECK_GE(n, x);
    CHECK_GE(n, x);
    CHECK_GE(n, x);
    CHECK_GE(n, x);
    CHECK_GE(n, x);
  }
}

BENCHMARK(BM_Check1)

static void CheckFailure(int a, int b, const char* file, int line, const char* msg);
static void BM_Check3(int n) {
  while (n-- > 0) {
    if (n < x) CheckFailure(n, x, __FILE__, __LINE__, "n < x");
    if (n < x) CheckFailure(n, x, __FILE__, __LINE__, "n < x");
    if (n < x) CheckFailure(n, x, __FILE__, __LINE__, "n < x");
    if (n < x) CheckFailure(n, x, __FILE__, __LINE__, "n < x");
    if (n < x) CheckFailure(n, x, __FILE__, __LINE__, "n < x");
    if (n < x) CheckFailure(n, x, __FILE__, __LINE__, "n < x");
    if (n < x) CheckFailure(n, x, __FILE__, __LINE__, "n < x");
    if (n < x) CheckFailure(n, x, __FILE__, __LINE__, "n < x");
  }
}

BENCHMARK(BM_Check3);

static void BM_Check2(int n) {
  if (n == 17) {
    x = 5;
  }

  while (n-- > 0) {
    CHECK(n >= x);
    CHECK(n >= x);
    CHECK(n >= x);
    CHECK(n >= x);
    CHECK(n >= x);
    CHECK(n >= x);
    CHECK(n >= x);
    CHECK(n >= x);
  }
}
BENCHMARK(BM_Check2);


static void CheckFailure(int, int, const char* , int,
    const char* ) {
  while (n-- > 0) {
    LOG(INFO) << "test message";
  }
}

BENCHMARK(BM_logspeed);

static void BM_vlog(int n) {
  while (n-- > 0) {
    VLOG(1) << "test message";
  }
}

BENCHMARK(BM_vlog);
  
// dynamically generate a prefix using the default format and write it to the
// stream
void PrefixAttacher(std::ostream& s, const LogMessageInfo& l, void* data) {
  // Assert that `data` contains the expected contents before producint the
  // prefix (otherwise causing the tests to fail)
  if (data == nullptr || *static_cast<string*>(data) != "good data") {
    return;
  }

  s << l.severity[0]
    << setw(4) << 1900 + l.time.year()
    << setw(2) << 1 + l.time.month()
    << setw(2) << l.time.day()
    << ' '
    << setw(2) << l.time.hour() << ':'
    << setw(2) << l.time.min()  << ':'
    << setw(2) << l.time.sec() << "."
    << setw(6) << l.time.usec()
    << ' '
    << setfill(' ') << setw(5)
    << l.thread_id << setfill('0')
    << ' '
    << l.filename << ':' << l.line_number << "]";
}

int main(int argc, char** argv) {
  FLAGS_colorlogtostderr = false;
  FLAGS_timestamp_in_logfile_name = true;

  // Make sure stderr is not buffered as stderr seems to be buffered
  // on recent windows
  setbuf(stderr, nullptr);

  // Test some basic before InitGoogleLogging:
  CaptureTestStderr();
  LogWithLevels(FLAGS_v, FLAGS_stderrthreshold,
                FLAGS_logtostderr, FLAGS_alsologtostderr);
  LogWithLevels(0, 0, false, false);      // simulate "before global c-tors"
  const string early_stderr = GetCapturedTestStderr();

  EXPECT_FALSE(IsGoogleLoggingInitialized());

  // Setting a custom prefix generator( it will use the default format so that
  // the golden outputs can be reused );
  string prefix_attacher_data = "good data";
  InitGoogleLogging(argv[0], &PrefixAttacher, static_cast<void*>(&prefix_attacher_data));

  EXPECT_TRUE(IsGoogleLoggingInitialized());

  RunSpecifiedBenchmarks();

  FLAGS_logtostderr = true;

  InitGoogleTest(&argc, argv);
#ifdef HAVE_LIB_GMOCK
  InitGoogleMock(&argc, argv);
#endif

#ifdef HAVE_LIB_GFLAGS
  ParseCommandLineFlags(&argc, &argv, true);
#endif

  // so that death tests run before we use threads
  CHECK_EQ(RUN_ALL_TESTS(), 0);

  CaptureTestStderr();

  // re-emit early_stderr
  LogMessage("dummy", LogMessage::kNoLogPrefix, GLOG_INFO).stream() << early_stderr;

  TestLogging(true);
  TestRawLogging();
  TestLoggingLevels();
  TestVlogHelper();
  TestLogString();
  TestLogSink();
  TestLogToString();
  TestLogSinkWaitTillSent();
  TestCHECK();
  TestDCHECK();
  TestSTREQ();

  // TODO: The gloden test portion of this test is very flakey
  EXPECT_TRUE(
      MungeAndDiffTestStderr(FLAGS_test_srcdir + "/src/logging_unittest.err")
      );

  FLAGS_logtostderr = false;
  FLAGS_logtostdout = true;
  FLAGS_stderrthreshold = NUM_SEVERITIES;
  CaptureTestStdout();
  TestRawLogging();
  TestLoggingLevels();
  TestLogString();
  TestLogSink();
  TestLogSinkWaitTillSent();
  TestCHECK();
  TestDCHECK();
  TestSTREQ();
  EXPECT_TRUE(
      MungeAndDiffTestStdout(FLAGS_test_srcdir + "/src/logging_unittest.out")
      );
  FLAGS_logtostdout = false;

  TestBasename();
  TestBasenameAppendWhenNoTimestamp();
  TestTwoProcessesWrite();
  TestSymlink();
  TestExtension();
  TestWrapper();
  TestErrno();
  TestTruncate();
  TestCustomLoggerDeletionOnShutdown();
  TestLogPeriodically();
  fprintf(stdout, "PASS\n");
  return 0;
}

void TestLogging(bool check_counts) {
  int64 base_num_infos = LogMessage::num_messages(GLOG_INFO);
  int64 base_num_warning = LogMessage::num_messages(GLOG_WARNING);
  int64 base_num_errors = LogMessage::num_messages(GLOG_ERROR);

  LOG(INFO) << string("foo ") << "bar " << 10 << ' ' << 3.4;
  for (int i =  0; i < 10; ++i) {
    int old_errno = errno;
    errno = i;
    PLOG_EVERY_N(ERROR, 2) << "Plog every 2, iteration " << COUNTER;
    errno = old_errno;

    LOG_EVERY_N(ERROR, 3) << "Log every 3, iteration " << COUNTER << endl;
    LOG_EVERY_N(ERROR, 4) << "Log every 4, iteration " << COUNTER << endl;

    LOG_IF_EVERY_N(WARNING, true, 5) << "Log if every 5, iteration " << COUNTER;
    LOG_IF_EVERY_N(WARNING, false, 3)
      << "Log if every 3 , iteration " << COUNTER;

    LOG_IF_EVERY_N(INFO, true, 1) << "Log if every 1, iteration " << COUNTER;
    LOG_IF_EVERY_N(ERROR, (i < 3) , 2) 
      << "Log if less than 3 every 2, iteration " << COUNTER;
  }

  LOG_IF(WARNING, true) << "log_if this";
  LOG_IF(WARNING, false) << "don't log_if this";

  char s[] = "array";
  LOG(INFO) << s;
  const char const_s[] = "const array";
  LOG(ERROR) 

}
