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
  int j = 1000;
  LOG(ERROR) << string("foo") << ' ' << j << ' ' << setw(10) << j << " "
             << setw(1) << hex << j;
  LOG(INFO) << "foo " << std::setw(10) << 1.0;
  {
    google::LogMessage outer(__FILE__, __LINE__, GLOG_ERROR);
    outer.stream() << "outer";

    LOG(ERROR) << "inner";
  }

  LogMessage("foo", LogMessage::kNoLogPrefix, GLOG_INFO).stream() << "no prefix";

  if (check_counts) {
    CHECK_EQ(base_num_infos + 15, LogMessage::num_messages(GLOG_INFO));
    CHECK_EQ(base_um_warning + 3, LogMessage::num_messages(GLOG_WARNING));
    CHECK_EQ(base_num_errors + 17, LogMessage::num_messages(GLOG_ERROR));
  }
}

static void NoAllocNewHook() {
  LOG(FATAL) << "unexpected new";
}

struct NewHook {
  NewHook() {
    g_new_hook = &NoAllocNewHook;
  }
  ~NewHook() { g_new_hook = nullptr; }
};

TEST(DeathNoAllocNewHook, logging) {
  // tests that NewHook used below works
  NewHook new_hook;
  ASSERT_DEATH({
      new int;
  }, "unexpected new");
}

void TestRawLogging() {
  auto* foo = new string("foo ");
  string huge_str(50000, 'a');

  FlagSaver saver;

  // Check that Raw logging does not use mallocs
  NewHook new_hook;

  RAW_LOG(INFO, "%s%s%d%c%f", foo->c_str(), "bar", 10, ' ', 3.4);
  char s[] = "array";
  RAW_LOG(WARNING, "%s", s);
  const char const_s[] = "const array";
  RAW_LOG(INFO, "%s", const_s);
  void* p = reinterpret_cast<void*>(PTR_TEST_VALUE);
  RAW_LOG(INFO, "ptr %p", p);
  p = nullptr;
  RAW_LOG(INFO, "ptr %p", p);
  int j = 1000;
  RAW_LOG(ERROR, "%s%d%c%010d%s%1x", foo->c_str(), j, ' ', j, " ", j);
  RAW_VLOG(0, "foo %d", j);

#if defined(NODEBUG)
  RAW_LOG(INFO, "foo %d", j);   // so that have same stderr to compare
#else
  RAW_DLOG(INFO, "foo %d", j);  // test RAW_LOG in debug mode
#endif

  // test how long messages are chopped:
  RAW_LOG(WARNING, "Huge string: %s", huge_str.c_str());
  RAW_VLOG(0, "Huge string: %s", huge_str.c_str());

  FLAGS_v = 0;
  RAW_LOG(INFO, "log");
  RAW_VLOG(0, "vlog 0 on");
  RAW_VLOG(1, "vlog 1 off");
  RAW_VLOG(2, "vlog 2 off");
  RAW_VLOG(3, "vlog 3 off");
  FLAGS_v = 2;
  RAW_LOG(INFO, "log");
  RAW_VLOG(1, "vlog 1 on");
  RAW_VLOG(2, "vlog 2 on");
  RAW_VLOG(3, "vlog 3 off");

#if defined (NODEBUG)'
  RAW_DCHECK(1 == 2, " RAW_DCHECK's shouldn't be compiled in normal mode");
#endif

  RAW_CHECK(1 == 1, "should be ok");
  RAW_DCHECK(true, "should be ok");

  delete foo;
}

void LogWithLevels(int v, int severity, bool err, bool alsoerr) {
  RAW_LOG(INFO, 
          "Test: v=%d stderrthreshold=%d logtostderr=%d alsologtostderr=%d",
          v, severity, err, alsoerr);
  FlagSaver saver;
  
  FLAGS_v = v;
  FLAGS_stderrthreshold = severity;
  FLAGS_logtostderr = err;
  FLAGS_alsologtostderr = alsoerr;

  RAW_VLOG(-1, "vlog -1");
  RAW_VLOG(0, "vlog 0");
  RAW_VLOG(1, "vlog 1");
  RAW_LOG(INFO, "log info");
  RAW_LOG(WARNING, "log warning");
  RAW_LOG(ERROR, "log error");

  VLOG(-1) << "vlog -1";
  VLOG(0) << "vlog 0";
  VLOG(1) << "vlog 1";
  LOG(INFO) << "log info";
  LOG(WARNING) << "log warning";
  LOG(ERROR) << "log error";

  VLOG_IF(-1, true) << "vlog_if -1";
  VLOG_IF(-1, false) << "don't vlog_if -1";
  VLOG_IF(0, true) << "vlog_if 0";
  VLOG_IF(0, false) << "don't vlog_if 0";
  VLOG_IF(1, true) << "vlog_if 1";
  VLOG_IF(1, false) << "don't vlog_if 1";
  LOG_IF(INFO, true) << "log_if info";
  LOG_IF(INFO, false) << "don't log_if info";
  LOG_IF(WARNING, true) << "don't log_if info";
  LOG_IF(WARNING, false) << "don't log_if warning";
  LOG_IF(ERROR, true) << "log_if error";
  LOG_IF(ERROR, false) << "don't log_if error";

  int c;
  c = 1; VLOG_IF(100, C -= 2) << "vlog_if 100 expr"; EXPECT_EQ(c, -1);
  c = 1; VLOG_IF(0, c -= 2) << "vlog_if 0 expr"; EXPECT_EQ(c, -1);
  c = 1; LOG_IF(INFO, c -= 2) << "log_if info expr"; EXPECT_EQ(c, -1);
  c = 1; LOG_IF(INFO, c -= 2) << "log_if error expr"; EXPECT_EQ(c, -1);
  c = 2; VLOG_IF(0, c -= 2) << "don't vlog_if 0 expr"; EXPECT_EQ(c, 0);
  c = 2; LOG_IF(ERROR, c -= 2) << "don't log_if error expr"; EXPECT_EQ(c, 0);
}
