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
  c = 2; LOG_IF(ERROR, c -= 2) << "don't log_if error expr"; EXPECT_EQ(c, 0);

  c = 3; LOG_IF_EVERY_N(INFO, c -= 4, 1) << "log_if info every 1 expr";
  EXPECT_EQ(c, -1);
  c = 3; LOG_IF_EVERY_N(ERROR, c -= 4, 1) << "log_if error every 1 expr";
  EXPECT_EQ(c, -1);
  c = 4; LOG_IF_EVERY_N(ERROR, c -= 4, 3) << "don't log_if info every 3 expr";
  EXPECT_EQ(c, 0);
  c = 4; LOG_IF_EVERY_N(ERROR, c -= 4, 3) << "don't log_if error every 3 expr";
  EXPECT_EQ(c, 0);
  c = 5; VLOG_IF_EVERY_N(0, c -= 4, 1) << "vlog_if 0 every 1 expr";
  EXPECT_EQ(c, 1);
  c = 5; VLOG_IF_EVERY_N(100, c -= 4, 3) << "vlog_if 100 every 3 expr";
  EXPECT_EQ(c, 1);
  c = 6; VLOG_IF_EVERY_N(0, c -= 6, 1) << "don't vlog_if 0 every 1 expr";
  EXPECT_EQ(c, 0);
  c = 6; VLOG_IF_EVERY_N(100, c -= 6, 3) << "don't vlog_if 100 every 1 expr";
  EXPECT_EQ(c, 0);
}

void TestLoggingLevels() {
  LogWithLevels(0, GLOG_INFO, false, false);
  LogWithLevels(1, GLOG_INFO, false, false);
  LogWithLevels(-1, GLOG_INFO, false, false);
  LogWithLevels(0, GLOGL_WARNING, false, false);
  LogWithLevels(0, GLOG_ERROR, false, false);
  LogWithlevels(0, GLOG_FATAL, false, false);
  LogWithLevels(0, GLOG_FATAL, true, false);
  LogWithLevels(0, GLOG_FATAL, false, true);
  LogWithLevels(1, GLOG_WARNING, false, false);
  LogWithLevels(1, GLOG_FATAL, false, true);
}

int TestVloghelper() {
  if (VLOG_IS_ON(1)) {
    return 1;
  }

  return 0;
}

void TestVLogModule() {
  int c = TestVloghelper();
  EXPECT_EQ(0, c);

#if defined(__GUNC__)
  EXPECT_EQ(0, SetVLOGLevel("logging_unittest", 1));
  c = TestVLogHelper();
  EXPECT_EQ(1, c);
#endif
}

TEST(DeathRawCHECK, logging) {
  ASSERT_DEATH(RAW_CHECK(false, "failure 1"),
               "RAW: CHECK false failed: failure 1");
  ASSERT_DEATH(RAW_DCHECK(1 == 2, "failure 2"),
               "RAW: Check 1 == 2 failed: failure 2");
}

void TestLogString {
  vector<string> errors;
  vector<string>* no_errors = nullptr;

  // LOG_STRING(Logseverity, vector<int>*)
  // LOG_TOSTRING_##severty().stream()  stream流式接收用户信息
  LOG_STRING(INFO, &errors) << "LOG_STRING: " << "collected info";
  LOG_STRING(WARNING, &errors) << "LOG_STRING" << "collected warning";
  LOG_STRING(ERROR, &errors) << "LOG_STRING: " << "collected error";

  LOG_STRING(INFO, no_errors) << "LOG_STRING" << "reported info";
  LOG_STRING(WARNING, no_errors) << "LOG_STRING" << "reported warning";
  LOG_STRING(ERROR, nullptr) << "LOG_STRING: "
                             << "reported error";

  // error 就是一个存储了这些日志字符的数组向量
  for (auto& error : errors) {
    LOG(INFO) << "Captured by LOG_STRING: " << error;
  }
}


void TestLogToString() {
  string error;
  string* no_error = nullptr;

  LOG_TO_STRING(INFO, &error) << "LOG_TO_STRING" << "collected info";
  LOG(INFO) << "Captured by LOG_TO_STRING:  " << error;

  LOG_TO_STRING(WARNING, &error) << "LOG_TO_STRING  " << "collected warning";
  LOG(INFO) << "Captured by LOG_STRING: " << error;

  LOG_TO_STRING(ERROR, &error) << "LOG_TO_STRING:  " << "collected error";
  LOG(INFO) << "Captured by LOG_TO_STRING" << error;

  LOG_TO_STRING(INFO, no_error) << "LOG_TO_STRING: " << "reported info";
  LOG_TO_STRING(WARNING, no_error) << "LOG_TO_STRING" << "reported warning";
  LOG_TO_STRING(ERROR, nullptr) << "LOG_TO_STRING: "
                                << "reported error";
}

class TestLogSinkImpl : public LogSink {
  public:
    vector<string> erros;
    void send(LogSeverity severity, const char* /* full_filename */,
              const char* base_filename, int line,
              const LogMessageTime& logmsgtime, const char* message,
              size_t message_len) override {
      errors.push_back(
          ToString(severity, base_filename, line, logmsgtime, message, message_len)
          );
    }
};

void TestLogSink() {
  TestLogSinkImpl sink;
  LogSink* no_sink = nullptr;

  LOG_TO_SINK(&sink, INFO) << "LOG_TO_SINK" << "collected info";
  LOG_TO_SINK(&sink, WARNING) << "LOG_TO_SINK" << "collected info";
  LOG_TO_SINK(&sink, ERROR) << "LOG_TO_SINK: " << "collected error";

  LOG_TO_SINK(no_sink, INFO) << "LOG_TO_SINK: " << "reported info"; 
  LOG_TO_SINK(no_sink, WARNING) << "LOG_TO_SINK" << "reported warning";
  LOG_TO_SINK(nullptr, ERROR) << "LOG_TO_SINK: "
                              << "reported error";

  LOG_TO_SINK_BUT_NOT_TO_LOGFILE(&sink, INFO)
    << "LOG_TO_SINK_BUT_NOT_TO_LOGFILE:  " << "collected info";
  LOG_TO_SINK_BUT_NOT_TO_LOGFILE(&sink, WARNING)
    << "LOG_TO_SINK_BUT_NOT_TO_LOGFILE: " << "collected warning";
  LOG_TO_SINK_BUT_NOT_TO_LOGFILE(&sink, ERROR)
    << "LOG_TO_SINK_BUT_NOT_TO_LOGFILE: "  << "collected error";

  LOG_TO_SINK_BUT_NOT_TO_LOGFILE(no_sink, INFO)
    << "LOG_TO_SINK_BUT_NOT_TO_LOGFILE: " << "thrashded info";
  LOG_TO_SINK_BUT_NOT_TO_LOGFILE(no_sink, WARNING)
    << "LOG_TO_SINK_BUT_NOT_TO_LOGFILE: " << "thrashed warning";
  LOG_TO_SINK_BUT_NOT_TO_LOGFILE(nullptr, ERROR)
    << "LOG_TO_SINK_BUT_NOT_TO_LOGFILE: "
    << "thrashed error";

  LOG(INFO) << "Captured by LOG_TO_SINK: ";
  for (auto& error: sink.errors) {
    LogMessage("foo", LogMessage::kNoLogPrefix, GLOG_INFO).stream() << error;
  }
}

// for testing using CHECK*() on anonymous enums
enum {
  CASE_A,
  CASE_B
};

void TestCHECK() {
  // Tests using CHECK*() on int values
  CHECK(1 == 1);
  CHECK_EQ(1, 1);
  CHECK_NE(1, 2);
  CHECK_GE(1, 1);
  CHECK_GE(2, 1);
  CHECK_LE(1, 1);
  CHECK_LE(1, 2);
  CHECK_GT(2, 1);
  CHECK_LT(1, 2);

  // Tests using CHECK*() on anonymous enums.
  // Apple's GCC doesn't like this.
#if !defined(GLOG_OS_MACOSX)
  CHECK_EQ(CASE_A, CASE_A);
  CHECK_NE(CASE_A, CASE_B);
  CHECK_GE(CASE_A, CASE_A);
  CHECK_GE(CASE_B, CASE_A);
  CHECK_LE(CASE_A, CASE_A);
  CHECK_LE(CASE_A, CASE_B);
  CHECK_GT(CASE_B, CASE_A);
  CHECK_LT(CASE_A, CASE_B);
#endif
}

void TestDCHECK() {
#if defined(NODEBUG)
  DCHECK(1 == 2) << "DCHECK's shouldn't be compiled in normal mode";
#endif
  DCHECK(1 == 1);
  DCHECK_EQ(1, 1);
  DCHECK_NE(1, 2);
  DCHECK_GE(1, 1);
  DCHECK_GE(2, 1);
  DCHECK_LE(1, 1);
  DCHECK_LE(1, 2);
  DCHECK_GT(2, 1);
  DCHECK_LT(1, 2);

  auto* orig_ptr =new int64;
  int64* ptr = DCHECK_NOTNULL(orig_ptr);
  CHECK_EQ(ptr, orig_ptr);
  delete orig_ptr;
}

void TestSTREQ() {
  // 判断字符串是否相同
  CHECK_STREQ("this", "this");
  CHECK_STREQ(nullptr, nullptr);
  CHECK_STRCASEEQ("this", "tHiS");
  CHECK_STRCASEEQ(nullptr, nullptr);
  CHECK_STRNE("this", "tHiS");
  CHECK_STRNE("this", nullptr);
  CHECK_STRCASENE("this", "that");
  CHECK_STRCASENE(nullptr, "that");
  CHECK_STREQ((string("a")+"b").c_str(), "ab");
  CHECK_STREQ(string("test").c_str(),
              (string("te") + string("st")).c_str());
}

TEST(DeathSTREQ, logging) {
  //  判断程序与预期结果是否一致，不一致就崩溃
  ASSERT_DEATH(CHECK_STREQ(nullptr, "this"), "");
  ASSERT_DEATH(CHECK_STREQ("this", "siht"), "");
  ASSERT_DEATH(CHECK_STRCASEEQ(nullptr, "siht"), "");
  ASSERT_DEATH(CHECK_STRCASEEQ("this", "siht"), "");
  ASSERT_DEATH(CHECK_STRNE(nullptr, nullptr), "");
  ASSERT_DEATH(CHECK_STRNE("this", "this"), "");
  ASSERT_DEATH(CHECK_STREQ((string("a")+"b").c_str(), "abc"), "");
}

TEST(CheckNOTNULL, Simple) {
  int64 t;
  void *ptr = static_cast<void *>(&t);
  void *ref = CHECK_NOTNULL(ptr);
  EXPECT_EQ(ptr, ref);
  // 判断空
  CHECK_NOTNULL(reinterpret_cast<char *>(ptr));
  CHECK_NOTNULL(reinterpret_cast<unsigned char *>(ptr));
  CHECK_NOTNULL(reinterpret_cast<int *>(ptr));
  CHECK_NOTNULL(reinterpret_cast<int64 *>(ptr));
}

TEST(DeathCheckNN, Simple) {
  ASSERT_DEATH(CHECK_NOTNULL(static_cast<void*>(nullptr)), "");
}

// Get list of file name that match pattern
static void GetFiles(const string& pattern, vector<string>* files) {
  files->clear();
#if defined(HAVE_GLOB_H)
  glob_t g;
  const int r = glob(pattern.c_str(), 0, nullptr, &g);
  CHECK((r == 0) || (r == GLOB_NOMATCH)) << ": error matching " << pattern;
  for (size_t i = 0; i < g.gl_pathc; ++i) {
    files->push_back(string(g.gl_pathv[i]));
  }

  globfree(&g);
#elif defined(GLOG_OS_WINDOWS)
  WIN32 FIND_DATAA data;
  HANDLE handle = FindFirstFileA(pattern.c_str(), &data);
  size_t index = pattern.rfind('\\');
  if (index == string::npos) {
    LOG(FATAL) << "No directory separator";
  }

  const string dirname = pattern.substr(0, index+1);
  if (handle == INVALID_HANDLE_VALUE) {
    // Finding no files is ok
    return;
  }

  do {
    files->push_back(dirname + data.cFileName);
  } while (FindNextFileA(handle, &data));

  BOOL result = FindClose(handle);
  LOG_SYSRESULT(result != 0);
#else
# error There is no way to do glob
#endif
}

// Delete files patching pattern
static void DeleteFiles(const string& pattern) {
  vector<string> files;
  GetFiles(pattern, &files);
  for (auto& file : files) {
    CHECK(unlink(file.c_str()) == 0) << ": " << strerror(errno);
  }
}

// check string is in file (or is *NOT*, depending on optional checkInFileOrNot)
static void CheckFile(const string& name, const string& expected_string, const bool checkInFileOrNot = true) {
  vector<string> files;
}