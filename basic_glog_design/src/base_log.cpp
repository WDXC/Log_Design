#include "base_log.h"
#include <algorithm>
#include <assert.h>
#include <ctime>
#include <iomanip>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <syscall.h>
#include <unistd.h>
#include <vector>

using std::ostream;
using std::setfill;
using std::setw;
using std::string;
using std::vector;

pid_t GetTID() {
  // On Linux and MacOSX, we try to use gettid().
#if defined OS_LINUX || defined OS_MACOSX
#ifndef __NR_gettid
#ifdef OS_MACOSX
#define __NR_gettid SYS_gettid
#elif !defined __i386__
#error "Must define __NR_gettid for non-x86 platforms"
#else
#define __NR_gettid 224
#endif
#endif
  static bool lacks_gettid = false;
  if (!lacks_gettid) {
#if (defined(OS_MACOSX) && defined(HAVE_PTHREAD_THREADID_NP))
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
#endif // OS_LINUX || OS_MACOSX

  // If gettid() could not be used, we use one of the following.
#if defined OS_LINUX
  return getpid(); // Linux:  getpid returns thread ID when gettid is absent
#elif defined OS_WINDOWS && !defined OS_CYGWIN
  return static_cast<pid_t>(GetCurrentThreadId());
#elif defined(HAVE_PTHREAD)
  // If none of the techniques above worked, we use pthread_self().
  return (pid_t)(uintptr_t)pthread_self();
#else
  return -1;
#endif
}

const size_t QLog::kMaxLogMessageLen = 30000;

int64 QLog::num_messages_[NUM_SEVERITIES] = {0, 0, 0, 0};

GLOG_DEFINE_bool(log_utc_time, false, "Use UTC time for logging.");

GLOG_DEFINE_bool(alsologtostderr, BoolFromEnv("GOOGLE_ALSOLOGTOSTDERR", false),
                 "log messages go to stderr in addition to logfiles");

GLOG_DEFINE_int32(logbuflevel, 0,
                  "Buffer log message for at most this many seconds"
                  " (-1 means don't buffer; 0 means buffer INFO only;"
                  " ...)");
GLOG_DEFINE_int32(logemaillevel, 999,
                  "Email log messages logged at this level or higher"
                  " (0 means email all; 3 means email FATAL only;"
                  " ...)");
DEFINE_int32(stderrthreshold, GLOG_ERROR,
             "log messages at or above this level are copied to stderr in "
             "addition to logfiles. This flag obsoletes --alsologtostderr.");

GLOG_DEFINE_string(alsologtoemail, "",
                   "log messages go to these email addresses "
                   "in addition to logfiles");

static void ColoredWriteToStderrOrStdout(FILE *output, LogSeverity severity,
                                         const char *message, size_t len) {
  bool is_stdout = (output == stdout);
  fwrite(message, len, 1, output);
}

static void ColoredWriteToStderr(LogSeverity severity, const char *message,
                                 size_t len) {
  ColoredWriteToStderrOrStdout(stderr, severity, message, len);
}

static GLogColor SeverityToColor(LogSeverity severity) {
  assert(severity >= 0 && severity < NUM_SEVERITIES);
  GLogColor color = COLOR_DEFAULT;
  switch (severity) {
  case GLOG_INFO:
    color = COLOR_DEFAULT;
    break;
  case GLOG_WARNING:
    color = COLOR_YELLOW;
    break;
  case GLOG_ERROR:
  case GLOG_FATAL:
    color = COLOR_RED;
    break;
  default:
    // should never get here
    assert(false);
  }
  return color;
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

const char *const_basename(const char *filepath) {
  const char *base = strrchr(filepath, '/');
  return base ? (base + 1) : filepath;
}

struct QLog::LogMessageData {
  LogMessageData();

  char message_text_[QLog::kMaxLogMessageLen + 1];
  LogStream stream_;
  char severity_;
  int line_;
  void (QLog::*send_method_)();
  union {
    LogSink *sink_;
    std::vector<std::string> *outvec_;
    std::string *message_;
  };
  size_t num_prefix_chars_;
  size_t num_chars_to_log_;
  size_t num_chars_to_syslog_;
  const char *basename_;
  const char *fullname_;
  bool has_been_flushed_;
  bool first_fatal_;

private:
  LogMessageData(const LogMessageData &) = delete;
  void operator=(const LogMessageData &) = delete;
};

Logger::~Logger() = default;

class LogFileObject : public Logger {
public:
  LogFileObject(LogSeverity severity, const char *base_filename);
  ~LogFileObject() override;

  void Write(bool force_flush, // should we force a flush here?
             time_t timestamp, // Timestamp for this entry
             const char *message, size_t message_len) override;

  // Configuration options
  void SetBasename(const char *basename);
  void SetExtension(const char *ext);
  void SetSymlinkBasename(const char *symlink_basename);

  // Normal flushing routine
  void Flush() override;

  // It is the actual file length for the system loggers,
  // i.e., INFO, ERROR, etc.
  uint32 LogSize() override { return file_length_; }

  // Internal flush routine. Exposed so that FlushLogFilesUnsafe()
  // can avoid grabbing a lock. Usually Flush() calls it after
  // acquiring lock_;
  void FlushUnlocked();

private:
  static const uint32 kRolloverAttemptFrequency = 0x20;

  bool base_filename_selected_;
  string base_filename_;
  string symlink_basename_;
  string filename_extension_;
  FILE *file_{nullptr};
  LogSeverity severity_;
  uint32 bytes_since_flush_{0};
  uint32 dropped_mem_length_{0};
  uint32 file_length_{0};
  unsigned int rollover_attempt_;
  int64 next_flush_time_;
  WallTime start_time_;

  // Actually create a logfile using the value of base_filename_ and the
  // optional argument time_pid_string
  // REQUIRES: lock_ is held
  bool CreateLogfile(const string &time_pid_string);
};

class LogCleaner {
public:
  LogCleaner();

  // Setting overdue_days to 0 days will delete all logs.
  void Enable(unsigned int overdue_days);
  void Disable();

  // update next_cleanup_time_
  void UpdateCleanUpTime();

  void Run(bool base_filename_selected, const string &base_filename,
           const string &filename_extension);
  bool enabled() const { return enabled_; }

private:
  vector<string> GetOverdueLogNames(string log_directory, unsigned int days,
                                    const string &base_filename,
                                    const string &filename_extension) const;
  bool IsLogFromCurrentProject(const string &filepath,
                               const string &base_filename,
                               const string &filename_extension) const;

  bool enabled_{false};
  unsigned int overdue_days_{7};
  int64 next_cleanup_time_{0};
};

LogCleaner::LogCleaner() = default;

LogCleaner log_cleaner;

class LogDestination {
public:
  friend class QLog;
  friend void ReprintFatalMessage();
  friend Logger *GetLogger(LogSeverity);
  friend void SetLogger(LogSeverity, Logger *);

  static void SetLogDestination(LogSeverity severity,
                                const char *base_filename);
  static void SetLogSymlink(LogSeverity severity, const char *symlink_basename);
  static void AddLogSink(LogSink *destination);
  static void RemoveLogSink(LogSink *destination);
  static void SetLogFilenameExtension(const char *filename_extension);
  static void SetStderrLogging(LogSeverity min_severity);
  static void SetEmailLogging(LogSeverity min_severity, const char *addresses);
  static void LogToStderr();

  // Flush all log files that are at least at the given severity level
  static void FlushLogFiles(int min_severity);
  static void FlushLogFilesUnsafe(int min_severity);

  // we set the maximum size of our packet to be 1400, the logic beging
  // to prevent fragmentation
  // Really this number is arbitrary.
  static const int kNetworkBytes = 1400;

  static const string &hostname();
  static const bool &terminal_supports_color() {
    return terminal_supports_color_;
  }
  static void DeleteLogDestinations();

private:
  LogDestination(LogSeverity severity, const char *base_filename);
  ~LogDestination();

  // Take a log message of particular severity and log it to stderr
  // iff it's of a high enough severity to deserve it.
  static void MaybeLogToStderr(LogSeverity severity, const char *message,
                               size_t message_len, size_t prefix_len);

  // Take a log message of a particular severity and log it to email
  // iff it's of a high enough severity to deserve it.
  static void MaybeLogToEmail(LogSeverity severity, const char *message,
                              size_t len);
  // Take a log message of particular severity and log it to a file
  // iff the base filename is not "" (which means "don't" log to me")
  static void MaybeLogToLogfile(LogSeverity severity, time_t timestamp,
                                const char *message, size_t len);

  // Take a log message a particular severity and log it to the file
  // for the severity and also for all files with severity less than
  // this severity.
  static void LogToAllLogfiles(LogSeverity severity, time_t timestamp,
                               const char *message, size_t len);

  // Send logging info to all registered sinks.
  static void LogToSinks(LogSeverity severity, const char *full_filename,
                         const char *base_filename, int line,
                         const LogMessageTime &logmsgtime, const char *message,
                         size_t message_len);

  // Wait for all registered sinks via WaitTillSent
  // including the optional one in "data".
  static void WaitForSinks(QLog::LogMessageData *data);

  static LogDestination *log_destination(LogSeverity severity);

  Logger *GetLoggerImpl() const { return logger_; }
  void SetLoggerImpl(Logger *logger);
  void ResetLoggerImpl() { SetLoggerImpl(&fileobject_); }

private:
  LogFileObject fileobject_;
  Logger *logger_;
  static LogDestination *log_destinations_[NUM_SEVERITIES];
  static LogSeverity email_logging_severity_;
  static bool terminal_supports_color_;
  static string addresses_;
  static string hostname_;

  // arbitrary global logging destination
  static vector<LogSink *> *sinks_;

  // Disallow
  LogDestination(const LogDestination &) = delete;
  LogDestination operator=(const LogDestination &) = delete;
};

// Returns true iff terimnal supports using colors in output
static bool TerminalSupportsColor() {
  bool term_supports_color = false;
#ifdef OS_WINDOWS
  // on Windows TERM variable is usually not set, but the console does
  // support colors
  term_supports_color = true;
#else
  // On non-Windows platforms, we rely on the TERM variable
  const char *const term = getenv("TERM");
  if (term != nullptr && term[0] != '\0') {
    term_supports_color =
        !strcmp(term, "xterm") || !strcmp(term, "xterm-color") ||
        !strcmp(term, "xterm-256color") || !strcmp(term, "screen-256color") ||
        !strcmp(term, "konsole") || !strcmp(term, "konsole-16color") ||
        !strcmp(term, "konsole-256color") || !strcmp(term, "screen") ||
        !strcmp(term, "linux") || !strcmp(term, "cygwin");
  }
#endif
  return term_supports_color;
}

static void GetHostName(string *hostname) {
#if defined(HAVE_SYS_UTSNAME_H)
  struct utsname buf;
  if (uname(&buf) < 0) {
    // ensure null termination on failure
    *buf.nodename = '\0';
  }
  *hostname = buf.nodename;
#elif defined(OS_WINDOWS)
  char buf[MAX_COMPUTERNAME_LENGTH + 1];
  DWORD len = MAX_COMPUTERNAME_LENGTH + 1;
  if (GetComputerNameA(buf, &len)) {
    *hostname = buf;
  } else {
    hostname->clear();
  }
#else
#warning There is no way to retrieve the host name.
  *hostname = "(unknown)";
#endif
}

static bool SendEmailInternal(const char* dest, const char* subject,
        const char* body, bool use_logging) {
    
}

void InitInvocationName(const char *argv0) {
  const char *slash = strchr(argv0, '/');
  g_program_invocation_short_name = slash ? slash + 1 : argv0;
}

const char *ProgramInvocationShortName() {
  if (g_program_invocation_short_name != nullptr) {
    return g_program_invocation_short_name;
  } else {
    return "UNKNOW";
  }
}

LogSeverity LogDestination::email_logging_severity_ = 99999;

string LogDestination::addresses_;
string LogDestination::hostname_;

vector<LogSink *> *LogDestination::sinks_ = nullptr;
bool LogDestination::terminal_supports_color_ = TerminalSupportsColor();

const string &LogDestination::hostname() {
  if (hostname_.empty()) {
    GetHostName(&hostname_);
    if (hostname_.empty()) {
      hostname_ = "(unknown)";
    }
  }
  return hostname_;
}

LogDestination::LogDestination(LogSeverity severity, const char *base_filename)
    : fileobject_(severity, base_filename), logger_(&fileobject_) {}

LogDestination::~LogDestination() { ResetLoggerImpl(); }

void LogDestination::SetLoggerImpl(Logger *logger) {
  if (logger_ == logger) {
    // Prevent releasing currently held sink on reset
    return;
  }

  if (logger_ && logger_ != &fileobject_) {
    delete logger_;
  }

  logger_ = logger;
}

inline void LogDestination::FlushLogFilesUnsafe(int min_severity) {
  // assume we have the log_mutex or we simply don't care
  // about it
  for (int i = min_severity; i < NUM_SEVERITIES; ++i) {
    LogDestination *log = log_destinations_[i];
    if (log != nullptr) {
      // Flush the base fileObject_ logger directly instead of going
      // through any wrappers to reduce change of deadlock
      log->fileobject_.FlushUnlocked();
    }
  }
}

inline void LogDestination::FlushLogFiles(int min_severity) {
  // Prevent any subtle race conditions by wrapping a mutex lock around
  // all this stuff.
  for (int i = min_severity; i < NUM_SEVERITIES; ++i) {
    LogDestination *log = log_destination(i);
    if (log != nullptr) {
      log->logger_->Flush();
    }
  }
}

inline void LogDestination::SetLogDestination(LogSeverity severity,
                                              const char *base_filename) {
  assert(severity >= 0 && severity < NUM_SEVERITIES);
  // Prevent any subtle race conditions by wrapping a mutex lock around
  // all this stuff.
  log_destination(severity)->fileobject_.SetBasename(base_filename);
}

inline void LogDestination::SetLogSymlink(LogSeverity severity,
                                          const char *symlink_basename) {
  log_destination(severity)->fileobject_.SetSymlinkBasename(symlink_basename);
}

inline void LogDestination::AddLogSink(LogSink *destination) {
  // Prevent any subtle race conditions by wrapping a mutex lock around
  // all this stuff
  if (!sinks_)
    sinks_ = new vector<LogSink *>;
  sinks_->push_back(destination);
}

inline void LogDestination::RemoveLogSink(LogSink *destination) {
  // Prevent any subtle race condition by wrapping a mutex lock around
  // all this stuff.
  // This doesn't keep the sinks in order
  if (sinks_) {
    sinks_->erase(std::remove(sinks_->begin(), sinks_->end(), destination),
                  sinks_->end());
  }
}

inline void LogDestination::SetLogFilenameExtension(const char *ext) {
  for (int severity = 0; severity < NUM_SEVERITIES; ++severity) {
    log_destination(severity)->fileobject_.SetExtension(ext);
  }
}

inline void LogDestination::LogToStderr() {
  // *Don't* put this stuff in a mutex lock, since SetStderrLogging &
  // SetLogDestination already do the locking!
  SetStderrLogging(0);
  for (int i = 0; i < NUM_SEVERITIES; ++i) {
    SetLogDestination(i, "");
  }
}

inline void LogDestination::SetEmailLogging(LogSeverity min_severity,
                                            const char *addresses) {
  assert(min_severity >= 0 && min_severity < NUM_SEVERITIES);
  // Prevent any subtle race condition by wrapping a mutex lock around
  // all this stuff.
  LogDestination::email_logging_severity_ = min_severity;
  LogDestination::addresses_ = addresses;
}

inline void LogDestination::MaybeLogToStderr(LogSeverity severity,
                                             const char *message,
                                             size_t message_len,
                                             size_t prefix_len) {

  if ((severity >= FLAGS_stderrthreshold) || FLAGS_alsologtostderr) {
    ColoredWriteToStderr(severity, message, message_len);
    (void)prefix_len;
  }
}

inline void LogDestination::MaybeLogToEmail(LogSeverity severity,
        const char *message, size_t len) {
    if (severity >= email_logging_severity_ ||
            severity >= FLAGS_logemaillevel) {
        string to(FLAGS_alsologtoemail);
        if (!addresses_.empty()) {
            if (!to.empty()) {
                to += ",";
            }
            to += addresses_;
        }
        const string subject(string("[LOG] ") + LogSeverityNames[severity] + ": " + 
                             ProgramInvocationShortName());
        string body(hostname());
        body += "\n\n";
        body.append(message, len);
    
        // should NOT use SendEmail(). The caller of this function holds the
        // log_mutex and SendEmail() calls LOG/VLOG which will block trying to 
        // acquire the log_mutex object. Use SendEmailInternal() and set use_logging
        // to false
        SendEmailInternal(to.c_str(), subject.c_str(), body.c_str(), false);
    }
}

inline void LogDestination::MaybeLogToLogfile(LogSeverity severity,
                                              time_t timestamp,
                                              const char *message, size_t len) {
  const bool should_flush = severity > FLAGS_logbuflevel;
}

LogFileObject::LogFileObject(LogSeverity severity, const char *base_filename)
    : base_filename_selected_(base_filename != nullptr),
      base_filename_((base_filename != nullptr) ? base_filename : ""),
      symlink_basename_(ProgramInvocationShortName()), filename_extension_(),
      severity_(severity), rollover_attempt_(kRolloverAttemptFrequency - 1),
      start_time_(WallTime_Now()) {
  assert(severity >= 0);
  assert(severity < NUM_SEVERITIES);
}

LogFileObject::~LogFileObject() {
  if (file_ != nullptr) {
    fclose(file_);
    file_ = nullptr;
  }
}

void LogFileObject::Write(bool force_flush, time_t timestamp,
                          const char *message, size_t message_len) {
  return;
}

void LogFileObject::Flush() { FlushUnlocked(); }

void LogFileObject::FlushUnlocked() {
  if (file_ != nullptr) {
    fflush(file_);
    bytes_since_flush_ = 0;
  }
  return;
}

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

void LogMessageTime::init(const std::tm &t, std::time_t timestamp,
                          WallTime now) {
  time_struct_ = t;
  timestamp_ = timestamp;
  usecs_ = static_cast<int32>((now - timestamp) * 1000000);

  CalcGmtOffset();
}

void LogMessageTime::CalcGmtOffset() {
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
  gmtoffset_ =
      static_cast<long int>(timestamp_ - gmt_sec + (isDst ? hour_secs : 0));
}

QLog::LogMessageData::LogMessageData()
    : stream_(message_text_, QLog::kMaxLogMessageLen, 0) {}

QLog::QLog(const char *file, int line) {
  Init(file, line, GLOG_INFO, &QLog::SendToLog);
}

void QLog::Init(const char *file, int line, LogSeverity severity,
                void (QLog::*send_method)()) {
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
  stream() << setw(2) << 1 + logmsgtime_.month() << setw(2) << logmsgtime_.day()
           << ' ' << setw(2) << logmsgtime_.hour() << ':' << setw(2)
           << logmsgtime_.min() << ':' << setw(2) << logmsgtime_.sec() << "."
           << setw(6) << logmsgtime_.usec() << ' ' << setfill(' ') << setw(5)
           << static_cast<unsigned int>(GetTID()) << setfill('0') << ' '
           << data_->basename_ << ':' << data_->line_ << "] ";
  stream().copyfmt(saved_fmt);
  data_->num_prefix_chars_ = data_->stream_.pcount();
}

void QLog::SendToLog() {
  ColoredWriteToStderr(data_->severity_, data_->message_text_,
                       data_->num_chars_to_log_);
}

const LogMessageTime &QLog::getLogMessageTime() const { return logmsgtime_; }

ostream &QLog::stream() { return data_->stream_; }

void QLog::Flush() {
  data_->num_chars_to_log_ = data_->stream_.pcount();
  data_->num_chars_to_syslog_ =
      data_->num_chars_to_log_ - data_->num_prefix_chars_;

  // Do we need to add a \n to the end of this message?
  bool append_newline =
      (data_->message_text_[data_->num_chars_to_log_ - 1] != '\n');
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
    data_->message_text_[data_->num_chars_to_log_ - 1] = original_final_char;
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
