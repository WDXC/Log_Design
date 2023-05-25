#include "base_log.h"
#include <vector>
#include <sys/time.h>
#include <ctime>
#include <string.h>
#include <iomanip>

using std::setw;
using std::string;
using std::setfill;
using std::ostream;

typedef std::int32_t int32;

const size_t QLog::kMaxLogMessageLen = 30000;

int64 QLog::num_messages_[NUM_SEVERITIES] = {0, 0, 0, 0};

const char* const LogSeverityNames[NUM_SEVERITIES] = {
  "INFO", "WARNING", "ERROR", "FATAL"
};

GLOG_DEFINE_bool(log_utc_time, false,
    "Use UTC time for logging.");


pid_t GetTID() {
  // On Linux and MacOSX, we try to use gettid().
#if defined GLOG_OS_LINUX || defined GLOG_OS_MACOSX
#ifndef __NR_gettid
#ifdef GLOG_OS_MACOSX
#define __NR_gettid SYS_gettid
#elif ! defined __i386__
#error "Must define __NR_gettid for non-x86 platforms"
#else
#define __NR_gettid 224
#endif
#endif
  static bool lacks_gettid = false;
  if (!lacks_gettid) {
#if (defined(GLOG_OS_MACOSX) && defined(HAVE_PTHREAD_THREADID_NP))
    uint64_t tid64;
    const int error = pthread_threadid_np(nullptr, &tid64);
    pid_t tid = error ? -1 : static_cast<pid_t>(tid64);
#else
    auto tid = static_cast<pid_t>(syscall(__NR_gettid));
#endif
    if (tid != -1) {
      return tid;
    }
    // Technically, this variable has to be volatile, but there is a small
    // performance penalty in accessing volatile variables and there should
    // not be any serious adverse effect if a thread does not immediately see
    // the value change to "true".
    lacks_gettid = true;
  }
#endif  // GLOG_OS_LINUX || GLOG_OS_MACOSX

  // If gettid() could not be used, we use one of the following.
#if defined GLOG_OS_LINUX
  return getpid();  // Linux:  getpid returns thread ID when gettid is absent
#elif defined GLOG_OS_WINDOWS && !defined GLOG_OS_CYGWIN
  return static_cast<pid_t>(GetCurrentThreadId());
#elif defined(HAVE_PTHREAD)
  // If none of the techniques above worked, we use pthread_self().
  return (pid_t)(uintptr_t)pthread_self();
#else
  return -1;
#endif
}



static void ColoredWriteToStderrOrStdout(FILE* output, LogSeverity severity,
    const char* message, size_t len) {
  bool is_stdout = (output == stdout);
    fwrite(message, len, 1, output);
    int m = 2;
}

static void ColoredWriteToStderr(LogSeverity severity, const char* message,
    size_t len) {
  ColoredWriteToStderrOrStdout(stderr, severity, message, len);
}

int64 CycleClock_Now() {
  // TODO(hamaji): temporary impementation - it might be too slow.
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  return static_cast<int64>(tv.tv_sec) * 1000000 + tv.tv_usec;
}

WallTime WallTime_Now() {
  // Now, cycle clock is retuning microseconds since the epoch.
  return CycleClock_Now() * 0.000001;
}



const char* const_basename(const char* filepath) {
  const char* base = strrchr(filepath, '/');
#ifdef GLOG_OS_WINDOWS  // Look for either path separator in Windows
  if (!base)
    base = strrchr(filepath, '\\');
#endif
  return base ? (base+1) : filepath;
}

struct QLog::LogMessageData {
  LogMessageData();

  char message_text_[QLog::kMaxLogMessageLen+1];
  LogStream stream_;
  char severity_;
  int line_;
  void (QLog::*send_method_)();
  union {
    LogSink* sink_;
    std::vector<std::string>* outvec_;
    std::string* message_;
  };
  size_t num_prefix_chars_;
  size_t num_chars_to_log_;
  size_t num_chars_to_syslog_;
  const char* basename_;
  const char* fullname_;
  bool has_been_flushed_;
  bool first_fatal_;

  private:
    LogMessageData(const LogMessageData&) = delete;
    void operator=(const LogMessageData&) = delete;
};

LogMessageTime::LogMessageTime() 
  : time_struct_(), timestamp_(0), usecs_(0), gmtoffset_(0) {}

LogMessageTime::LogMessageTime(std::tm t) {
  std::time_t timestamp = std::mktime(&t);
  init(t, timestamp, 0);
}


LogMessageTime::LogMessageTime(std::time_t timestamp, WallTime now) {
  std::tm t;
  if (FLAGS_log_utc_time) {
    gmtime_r(&timestamp, &t);
  } else {
    localtime_r(&timestamp, &t);
  }
  init(t, timestamp, now);
}

void LogMessageTime::init(const std::tm& t, std::time_t timestamp, 
    WallTime now) {
  time_struct_ = t;
  timestamp_ = timestamp;
  usecs_ = static_cast<int32>((now-timestamp)*1000000);

  CalcGmtOffset();
}

void LogMessageTime::CalcGmtOffset () {
  std::tm gmt_struct;
  int isDst = 0;
  if (fLB::FLAGS_log_utc_time) {
    localtime_r(&timestamp_, &gmt_struct);
    isDst = gmt_struct.tm_isdst;
    gmt_struct = time_struct_;
  } else {
    isDst = time_struct_.tm_isdst;
    gmtime_r(&timestamp_, &gmt_struct);
  }

  time_t gmt_sec = mktime(&gmt_struct);
  const long hour_secs = 3600;
  
  // If the Delaylight Saving Time(isDst) is active subtract an hour from the
  // current timestamp
  gmtoffset_ = static_cast<long int>(timestamp_ - gmt_sec + (isDst ? hour_secs : 0));
}

QLog::LogMessageData::LogMessageData()
  : stream_(message_text_, QLog::kMaxLogMessageLen, 0) {

  }

QLog::QLog(const char* file, int line) {
  Init(file, line, GLOG_INFO, &QLog::SendToLog);
}

void QLog::Init(const char* file, int line, LogSeverity severity, void(QLog::*send_method)()) {
  allocated_ = nullptr;
  allocated_ = new LogMessageData();
  data_ = allocated_;

  data_->first_fatal_ = false;
  data_->severity_ = severity;
  data_->line_ = line;
  data_->send_method_ = send_method;
  data_->fullname_ = file;
  data_->has_been_flushed_ = false;
  data_->sink_ = nullptr;
  data_->outvec_ = nullptr;
  WallTime now = WallTime_Now();
  auto timestamp_now = static_cast<time_t>(now);
  logmsgtime_ = LogMessageTime(timestamp_now, now);

  data_->num_chars_to_syslog_ = 0;
  data_->num_chars_to_log_ = 0;
  data_->basename_ = const_basename(file);
  data_->fullname_ = file;
  data_->has_been_flushed_ = false;

  std::ios saved_fmt(nullptr);
  saved_fmt.copyfmt(stream());
  stream().fill('0');
  stream() << LogSeverityNames[severity][0];
        stream() << setw(2) << 1 + logmsgtime_.month() << setw(2)
               << logmsgtime_.day() << ' ' << setw(2) << logmsgtime_.hour()
               << ':' << setw(2) << logmsgtime_.min() << ':' << setw(2)
               << logmsgtime_.sec() << "." << setw(6) << logmsgtime_.usec()
               << ' ' << setfill(' ') << setw(5)
               << static_cast<unsigned int>(GetTID()) << setfill('0') << ' '
               << data_->basename_ << ':' << data_->line_ << "] ";
  stream().copyfmt(saved_fmt);
  data_->num_prefix_chars_ = data_->stream_.pcount();
}

void QLog::SendToLog() {
  ColoredWriteToStderr(data_->severity_, data_->message_text_,
                       data_->num_chars_to_log_);
}

const LogMessageTime& QLog::getLogMessageTime() const {
  return logmsgtime_;
}

ostream& QLog::stream() {
  return data_->stream_;
}

void QLog::Flush() {
  data_->num_chars_to_log_ = data_->stream_.pcount();
  data_->num_chars_to_syslog_ =
    data_->num_chars_to_log_ - data_->num_prefix_chars_;

  // Do we need to add a \n to the end of this message?
  bool append_newline =
      (data_->message_text_[data_->num_chars_to_log_-1] != '\n');
  char original_final_char = '\0';

  // If we do need to add a \n, we'll do it by violating the memory of the
  // ostrstream buffer.  This is quick, and we'll make sure to undo our
  // modification before anything else is done with the ostrstream.  It
  // would be preferable not to do things this way, but it seems to be
  // the best way to deal with this.
  if (append_newline) {
    original_final_char = data_->message_text_[data_->num_chars_to_log_];
    data_->message_text_[data_->num_chars_to_log_++] = '\n';
  }
  data_->message_text_[data_->num_chars_to_log_] = '\0';

  // Prevent any subtle race conditions by wrapping a mutex lock around
  // the actual logging action per se.
    (this->*(data_->send_method_))();
    ++num_messages_[static_cast<int>(data_->severity_)];
  if (append_newline) {
    // Fix the ostrstream back how it was before we screwed with it.
    // It's 99.44% certain that we don't need to worry about doing this.
    data_->message_text_[data_->num_chars_to_log_-1] = original_final_char;
  }

  // If errno was already set before we enter the logging call, we'll
  // set it back to that value when we return from the logging call.
  // It happens often that we log an error message after a syscall
  // failure, which can potentially set the errno to some other
  // values.  We would like to preserve the original errno.

  // Note that this message is now safely logged.  If we're asked to flush
  // again, as a result of destruction, say, we'll do nothing on future calls.
  data_->has_been_flushed_ = true;
}

QLog::~QLog() {
  Flush();
  data_->~LogMessageData();
}
