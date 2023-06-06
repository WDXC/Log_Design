#include "base_log.h"
#include <algorithm>
#include <assert.h>
#include <ctime>
#include <fcntl.h>
#include <iomanip>
#include <sstream>
#include <string.h>
#include <sys/dir.h>
#include <sys/stat.h>
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

std::string g_application_fingerprint;
static bool stop_writing = false;

int64 UsecToCycles(int64 usec) { return usec; }

const char possible_dir_delim[] = {'/'};

const size_t QLog::kMaxLogMessageLen = 30000;

static const char *DefaultLogDir() {
  const char *env;
  env = getenv("GOOGLE_LOG_DIR");
  if (env != nullptr && env[0] != '\0') {
    return env;
  }
  env = getenv("TEST_TMPDIR");
  if (env != nullptr && env[0] != '\0') {
    return env;
  }
  return "";
}

int64 QLog::num_messages_[NUM_SEVERITIES] = {0, 0, 0, 0};

GLOG_DEFINE_bool(log_utc_time, false, "Use UTC time for logging.");

GLOG_DEFINE_bool(
    drop_log_memory, true,
    "Drop in-memory buffers of log contents. "
    "Logs can grow very quickly and they are rarely read before they "
    "need to be evicted from memory. Instead, drop them from memory "
    "as soon as they are flushed to disk.");

GLOG_DEFINE_bool(log_file_header, true,
                 "Write the file header at the start of each log file");

GLOG_DEFINE_bool(stop_logging_if_full_disk, false,
                 "Stop attempting to log to disk if the disk if full");

GLOG_DEFINE_bool(timestamp_in_logfile_name,
                 BoolFromEnv("GOOGLE_TIMESTAMP_IN_LOGFILE_NAME", true),
                 "put a timestamp at the end of the log file name");

GLOG_DEFINE_bool(log_year_in_prefix, true,
                 "Include the year in the log prefix");

GLOG_DEFINE_bool(alsologtostderr, BoolFromEnv("GOOGLE_ALSOLOGTOSTDERR", false),
                 "log messages go to stderr in addition to logfiles");
GLOG_DEFINE_bool(logtostderr, BoolFromEnv("GOOGLE_LOGTOSTDERR", false),
                 "log messages go to stderr instead of logfiles");

GLOG_DEFINE_bool(logtostdout, BoolFromEnv("GOOGLE_LOGTOSTDOUT", false),
                 "log messages go to stdout instead of logfiles");

GLOG_DEFINE_int32(logcleansecs, 60 * 5, // every 5 minutes
                  "Clean overdue logs every this many second");

GLOG_DEFINE_int32(logbuflevel, 0,
                  "Buffer log message for at most this many seconds"
                  " (-1 means don't buffer; 0 means buffer INFO only;"
                  " ...)");
GLOG_DEFINE_int32(logemaillevel, 999,
                  "Email log messages logged at this level or higher"
                  " (0 means email all; 3 means email FATAL only;"
                  " ...)");
GLOG_DEFINE_int32(logfile_mode, 0664, "Log file mode/permissions.");

DEFINE_int32(stderrthreshold, GLOG_ERROR,
             "log messages at or above this level are copied to stderr in "
             "addition to logfiles. This flag obsoletes --alsologtostderr.");

GLOG_DEFINE_string(alsologtoemail, "",
                   "log messages go to these email addresses "
                   "in addition to logfiles");

GLOG_DEFINE_string(
    log_dir, DefaultLogDir(),
    "If specified, logfiles are written into this directory instead "
    "of the default logging directory");
GLOG_DEFINE_string(log_link, "",
                   "Put additional links to the log "
                   "files in this directory");

GLOG_DEFINE_uint32(max_log_size, 1800,
                   "approx. maximum log file size (in MB). A value of 0 will "
                   "be silently overridden to 1.");

enum { PATH_SEPARATOR = '/' };

string PrettyDuration(int secs) {
  std::stringstream result;
  int mins = secs / 60;
  int hours = mins / 60;
  mins = mins % 60;
  secs = secs % 60;
  result.fill('0');
  result << hours << ':' << setw(2) << mins << ':' << setw(2) << secs;
  return result.str();
}

static void ColoredWriteToStderrOrStdout(FILE *output, LogSeverity severity,
                                         const char *message, size_t len) {
  bool is_stdout = (output == stdout);
  fwrite(message, len, 1, output);
}

static uint32 MaxLogSize() {
  return (FLAGS_max_log_size > 0 && FLAGS_max_log_size < 4096
              ? FLAGS_max_log_size
              : 1);
}

const string MyUserName() {
  string name = getenv("USER");
  return name;
}

static void ColoredWriteToStdout(LogSeverity severity, const char *message,
                                 size_t len) {
  FILE *output = stdout;
  // We also need to send logs to the stderr when the severity is
  // higher or equal to the stderr threshold
  if (severity >= FLAGS_stderrthreshold) {
    output = stderr;
  }

  ColoredWriteToStderrOrStdout(output, severity, message, len);
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
  bool IsLogLastModifiedOver(const string &filepath, unsigned int days) const;

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

static bool SendEmailInternal(const char *dest, const char *subject,
                              const char *body, bool use_logging) {
  return false;
}

bool LogCleaner::IsLogLastModifiedOver(const string &filepath,
                                       unsigned int days) const {
  struct stat file_stat;

  if (stat(filepath.c_str(), &file_stat) == 0) {
    const time_t seconds_in_a_day = 60 * 60 * 24;
    time_t last_modified_time = file_stat.st_mtime;
    time_t current_time = time(nullptr);
    return difftime(current_time, last_modified_time) > days * seconds_in_a_day;
  }

  return false;
}

vector<string>
LogCleaner::GetOverdueLogNames(string log_directory, unsigned int days,
                               const string &base_filename,
                               const string &filename_extension) const {
  vector<string> overdue_log_names;

  DIR *dir;
  struct dirent *ent;

  if ((dir = opendir(log_directory.c_str()))) {
    while ((ent = readdir(dir))) {
      if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
        continue;
      }

      string filepath = ent->d_name;
      const char *const dir_delim_end =
          possible_dir_delim + sizeof(possible_dir_delim);

      if (!log_directory.empty() &&
          std::find(possible_dir_delim, dir_delim_end,
                    log_directory[log_directory.size()] - 1) != dir_delim_end) {
        filepath = log_directory + filepath;
      }

      if (IsLogFromCurrentProject(filepath, base_filename,
                                  filename_extension) &&
          IsLogLastModifiedOver(filepath, days)) {
        overdue_log_names.push_back(filepath);
      }
    }
    closedir(dir);
  }
  return overdue_log_names;
}


bool LogCleaner::IsLogFromCurrentProject(const string& filepath,
                                         const string& base_filename,
                                         const string& filename_extension) const {
  // We should remove duplicated delimiters from `base_filename`, e.g.,
  // before: "/tmp//<base_filename>.<create_time>.<pid>"
  // after:  "/tmp/<base_filename>.<create_time>.<pid>"
  string cleaned_base_filename;

  const char* const dir_delim_end =
      possible_dir_delim + sizeof(possible_dir_delim);

  size_t real_filepath_size = filepath.size();
  for (char c : base_filename) {
    if (cleaned_base_filename.empty()) {
      cleaned_base_filename += c;
    } else if (std::find(possible_dir_delim, dir_delim_end, c) ==
                   dir_delim_end ||
               (!cleaned_base_filename.empty() &&
                c != cleaned_base_filename[cleaned_base_filename.size() - 1])) {
      cleaned_base_filename += c;
    }
  }

  // Return early if the filename doesn't start with `cleaned_base_filename`.
  if (filepath.find(cleaned_base_filename) != 0) {
    return false;
  }

  // Check if in the string `filename_extension` is right next to
  // `cleaned_base_filename` in `filepath` if the user
  // has set a custom filename extension.
  if (!filename_extension.empty()) {
    if (cleaned_base_filename.size() >= real_filepath_size) {
      return false;
    }
    // for origin version, `filename_extension` is middle of the `filepath`.
    string ext = filepath.substr(cleaned_base_filename.size(), filename_extension.size());
    if (ext == filename_extension) {
      cleaned_base_filename += filename_extension;
    }
    else {
      // for new version, `filename_extension` is right of the `filepath`.
      if (filename_extension.size() >= real_filepath_size) {
        return false;
      }
      real_filepath_size = filepath.size() - filename_extension.size();
      if (filepath.substr(real_filepath_size) != filename_extension) {
        return false;
      }
    }
  }

  // The characters after `cleaned_base_filename` should match the format:
  // YYYYMMDD-HHMMSS.pid
  for (size_t i = cleaned_base_filename.size(); i < real_filepath_size; i++) {
    const char& c = filepath[i];

    if (i <= cleaned_base_filename.size() + 7) { // 0 ~ 7 : YYYYMMDD
      if (c < '0' || c > '9') { return false; }

    } else if (i == cleaned_base_filename.size() + 8) { // 8: -
      if (c != '-') { return false; }

    } else if (i <= cleaned_base_filename.size() + 14) { // 9 ~ 14: HHMMSS
      if (c < '0' || c > '9') { return false; }

    } else if (i == cleaned_base_filename.size() + 15) { // 15: .
      if (c != '.') { return false; }

    } else if (i >= cleaned_base_filename.size() + 16) { // 16+: pid
      if (c < '0' || c > '9') { return false; }
    }
  }

  return true;
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
  if (severity >= email_logging_severity_ || severity >= FLAGS_logemaillevel) {
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
  LogDestination *destination = log_destination(severity);
  destination->logger_->Write(should_flush, timestamp, message, len);
}

inline void LogDestination::LogToAllLogfiles(LogSeverity severity,
                                             time_t timestamp,
                                             const char *message, size_t len) {
  if (FLAGS_logtostdout) {
    ColoredWriteToStdout(severity, message, len);
  } else if (FLAGS_logtostderr) {
    ColoredWriteToStderr(severity, message, len);
  } else {
    for (int i = severity; i >= 0; --i) {
      LogDestination::MaybeLogToLogfile(i, timestamp, message, len);
    }
  }
}

inline void LogDestination::LogToSinks(LogSeverity severity,
                                       const char *full_filename,
                                       const char *base_filename, int line,
                                       const LogMessageTime &logmsgtime,
                                       const char *message,
                                       size_t message_len) {
  if (sinks_) {
    for (size_t i = sinks_->size(); i-- > 0;) {
      (*sinks_)[i]->send(severity, full_filename, base_filename, line,
                         logmsgtime, message, message_len);
    }
  }
}

inline void LogDestination::WaitForSinks(QLog::LogMessageData *data) {
  if (sinks_) {
    for (size_t i = sinks_->size(); i-- > 0;) {
      (*sinks_)[i]->WaitTillSent();
    }
  }

  const bool send_to_sink = true;
  if (send_to_sink && data->sink_ != nullptr) {
    data->sink_->WaitTillSent();
  }
}

LogDestination *LogDestination::log_destinations_[NUM_SEVERITIES];

inline LogDestination *LogDestination::log_destination(LogSeverity severity) {
  assert(severity >= 0 && severity < NUM_SEVERITIES);
  if (!log_destinations_[severity]) {
    log_destinations_[severity] = new LogDestination(severity, nullptr);
  }
  return log_destinations_[severity];
}

void LogDestination::DeleteLogDestinations() {
  for (auto &log_destination : log_destinations_) {
    delete log_destination;
    log_destination = nullptr;
  }
  delete sinks_;
  sinks_ = nullptr;
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

void LogFileObject::SetBasename(const char *basename) {
  base_filename_selected_ = true;
}

bool LogFileObject::CreateLogfile(const string &time_pid_string) {
  string string_filename = base_filename_;
  if (FLAGS_timestamp_in_logfile_name) {
    string_filename += time_pid_string;
  }

  string_filename += filename_extension_;
  const char *filename = string_filename.c_str();

  // only write to files, create if non-existant
  int flags = O_WRONLY | O_CREAT;
  if (FLAGS_timestamp_in_logfile_name) {
    flags = flags | O_EXCL;
  }
  int fd = open(filename, flags, static_cast<mode_t>(FLAGS_logfile_mode));
  if (fd == -1)
    return false;

  fcntl(fd, F_SETFD, FD_CLOEXEC);

  // flock is file lock
  static struct flock w_lock;

  w_lock.l_type = F_WRLCK;
  w_lock.l_start = 0;
  w_lock.l_whence = SEEK_SET;
  w_lock.l_len = 0;

  int wlock_ret = fcntl(fd, F_SETLK, &w_lock);
  if (wlock_ret == -1) {
    close(fd);
    return false;
  }

  file_ = fdopen(fd, "a");
  if (file_ == nullptr) {
    close(fd);
    if (FLAGS_timestamp_in_logfile_name) {
      unlink(filename); // Erase the half-baked evidence: an unusable log file,
                        // only if we just created it.
    }
    return false;
  }

  if (!symlink_basename_.empty()) {
    const char *slash = strrchr(filename, PATH_SEPARATOR);
    const string linkname =
        symlink_basename_ + '.' + LogSeverityNames[severity_];
    string linkpath;
    if (slash)
      linkpath = string(filename, static_cast<size_t>(slash - filename + 1));
    linkpath += linkname;
    unlink(linkpath.c_str());

    const char *linkdest = slash ? (slash + 1) : filename;
    if (symlink(linkdest, linkpath.c_str()) != 0) {
    }

    if (!FLAGS_log_link.empty()) {
      linkpath = FLAGS_log_link + "/" + linkname;
      unlink(linkpath.c_str());
      if (symlink(filename, linkpath.c_str()) != 0) {
      }
    }
  }
  return true;
}

void LogFileObject::Write(bool force_flush, time_t timestamp,
                          const char *message, size_t message_len) {
  if (base_filename_selected_ && base_filename_.empty()) {
    return;
  }

  if (file_length_ >> 20U >= MaxLogSize()) {
    if (file_ != nullptr)
      fclose(file_);
    file_ = nullptr;
    file_length_ = bytes_since_flush_ = dropped_mem_length_ = 0;
    rollover_attempt_ = kRolloverAttemptFrequency - 1;
  }

  if (file_ == nullptr) {
    if (++rollover_attempt_ != kRolloverAttemptFrequency)
      return;
    rollover_attempt_ = 0;
    struct ::tm tm_time;
    if (FLAGS_log_utc_time) {
      gmtime_r(&timestamp, &tm_time);
    } else {
      localtime_r(&timestamp, &tm_time);
    }

    // the logfile's filename will have the date/time & pid in it
    std::ostringstream time_pid_stream;
    time_pid_stream.fill('0');
    time_pid_stream << 1900 + tm_time.tm_year << setw(2) << 1 + tm_time.tm_mon
                    << setw(2) << tm_time.tm_mday << '-' << setw(2)
                    << tm_time.tm_hour << setw(2) << tm_time.tm_min << setw(2)
                    << tm_time.tm_sec << '.';

    const string &time_pid_string = time_pid_stream.str();

    if (base_filename_selected_) {
      if (!CreateLogfile(time_pid_string)) {
        perror("Could not create log file");
        fprintf(stderr, "COULD NOT CREATE LOGFILE '%S'!\n",
                time_pid_string.c_str());
        return;
      }
    } else {
      string stripped_filename(ProgramInvocationShortName());
      string hostname;
      GetHostName(&hostname);

      string uidname = MyUserName();
      if (uidname.empty())
        uidname = "invalid-user";

      stripped_filename = stripped_filename + '.' + hostname + '.' + uidname +
                          ".log." + LogSeverityNames[severity_] + '.';
      const vector<string> &log_dirs = GetLoggingDirectories();

      bool success = false;

      for (const auto &log_dir : log_dirs) {
        base_filename_ = log_dir + "/" + stripped_filename;
        if (CreateLogfile(time_pid_string)) {
          success = true;
          break;
        }
      }
      // If we never succeeded, we have to give up
      if (success == false) {
        perror("Could not create logging file");
        fprintf(stderr, "COULD NOT CREATE A LOGGINGFILE %s!",
                time_pid_string.c_str());
        return;
      }
    }

    // Write a header message into the log file
    if (FLAGS_log_file_header) {
      std::ostringstream file_header_stream;
      file_header_stream.fill('0');
      file_header_stream << "Log file created at: " << 1900 + tm_time.tm_year
                         << '/' << setw(2) << 1 + tm_time.tm_mon << '/'
                         << setw(2) << tm_time.tm_mday << ' ' << setw(2)
                         << tm_time.tm_hour << ':' << setw(2) << tm_time.tm_min
                         << ':' << setw(2) << tm_time.tm_sec
                         << (FLAGS_log_utc_time ? "UTC\n" : "\n")
                         << "Running  on machine: "
                         << LogDestination::hostname() << '\n';
      if (!g_application_fingerprint.empty()) {
        file_header_stream << "Application fingerprint: "
                           << g_application_fingerprint << '\n';
      }
      const char *const date_time_format = FLAGS_log_year_in_prefix
                                               ? "yyyymmdd hh:mm:ss.uuuuuu"
                                               : "mmdd hh:mm:ss.uuuuuu";
      file_header_stream << "Running during (h:mm:ss): "
                         << PrettyDuration(
                                static_cast<int>(WallTime_Now() - start_time_))
                         << '\n'
                         << "Log line format: [IWEF]" << date_time_format << " "
                         << "threadid file:line] msg" << '\n';

      const string &file_header_string = file_header_stream.str();

      const size_t header_len = file_header_string.size();
      fwrite(file_header_string.data(), 1, header_len, file_);
      file_length_ += header_len;
      bytes_since_flush_ += header_len;
    }
  }

  if (!stop_writing) {
    // fwrite() doesn't return an error when the disk is full, for
    // messages that are less than 4096 bytes.When the disk is full
    // it returns the message length for messages that are less than
    // 4096 bytes. fwrite() returns 4096 for message lengths that are
    // greater than 4096, thereby indicating an error
    errno = 0;
    fwrite(message, 1, message_len, file_);
    if (FLAGS_stop_logging_if_full_disk && errno == ENOSPC) {
      stop_writing = true;
      return;
    } else {
      file_length_ += message_len;
      bytes_since_flush_ += message_len;
    }
  } else {
    if (CycleClock_Now() >= next_flush_time_) {
      stop_writing = false; // check to see if disk has free space.
    }
    return;
  }
  // See important msgs *now*. Also, flush logs at least every 10^6 chars,
  // or every "FLAGS_logbufsecs" seconds.
  if (force_flush || (bytes_since_flush_ >= 100000) ||
      (CycleClock_Now() >= next_flush_time_)) {
    FlushUnlocked();
    // only consider files >= 3MiB
    if (FLAGS_drop_log_memory && file_length_ >= (3U << 20U)) {
      // Don't evict the most recent 1-2MiB so as not to impact a tailer
      // of the log file and to avoid page rounding issue on linux < 4.7
      uint32 total_drop_length =
          (file_length_ & ~((1U << 20U) - 1U)) - (1U << 20U);
      uint32 this_drop_length = total_drop_length - dropped_mem_length_;
      if (this_drop_length >= (2U << 20U)) {
        posix_fadvise(fileno(file_), static_cast<off_t>(dropped_mem_length_),
                      static_cast<off_t>(this_drop_length),
                      POSIX_FADV_DONTNEED);
        dropped_mem_length_ = total_drop_length;
      }
    }

    // Remove old logs
    if (log_cleaner.enabled()) {
      log_cleaner.Run(base_filename_selected_, base_filename_,
                      filename_extension_);
    }
  }
}

static void GetTempDirectories(vector<string> *list) {
  list->clear();
  const char *candidates[] = {
      getenv("TEST_TMPDIR"),
      getenv("TMPDIR"),
      getenv("TMP"),
      "./test",
  };

  for (auto d : candidates) {
    if (!d)
      continue;

    string dstr = d;
    if (dstr[dstr.size() - 1] != '/') {
      dstr += "/";
    }
    list->push_back(dstr);

    struct stat statbuf;
    if (!stat(d, &statbuf) && S_ISDIR(statbuf.st_mode)) {
      return;
    }
  }
}
static vector<string> *logging_directories_list;
const vector<string> &GetLoggingDirectories() {
  // Not strictly thread-safe but we're called early in InitGoogle().
  if (logging_directories_list == nullptr) {
    logging_directories_list = new vector<string>;

    if (!FLAGS_log_dir.empty()) {
      logging_directories_list->push_back(FLAGS_log_dir);
    } else {
      GetTempDirectories(logging_directories_list);
      logging_directories_list->push_back("./");
    }
  }
  return *logging_directories_list;
}

void LogCleaner::Enable(unsigned int overdue_days) {
  enabled_ = true;
  overdue_days_ = overdue_days;
}

void LogCleaner::Disable() { enabled_ = false; }

void LogCleaner::UpdateCleanUpTime() {
  const int64 next = (FLAGS_logcleansecs * 1000000);
  next_cleanup_time_ = CycleClock_Now() + UsecToCycles(next);
}

void LogCleaner::Run(bool base_filename_selected, const string &base_filename,
                     const string &filename_extension) {
  assert(enabled_);
  assert(!base_filename_selected || !base_filename.empty());

  // avoid scanning logs too frequently
  if (CycleClock_Now() < next_cleanup_time_) {
    return;
  }

  UpdateCleanUpTime();

  vector<string> dirs;

  if (!base_filename_selected) {
    dirs = GetLoggingDirectories();
  } else {
    size_t pos = base_filename.find_last_of(possible_dir_delim, string::npos,
                                            sizeof(possible_dir_delim));
    if (pos != string::npos) {
      string dir = base_filename.substr(0, pos + 1);
      dirs.push_back(dir);
    } else {
      dirs.emplace_back(".");
    }
  }
  for (auto &dir : dirs) {
    vector<string> logs = GetOverdueLogNames(dir, overdue_days_, base_filename,
                                             filename_extension);
    for (auto &log : logs) {
      static_cast<void>(unlink(log.c_str()));
    }
  }
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
  static bool already_warned_before_initgoogle = false;
  FLAGS_logtostderr = false;
  FLAGS_logtostdout = false;

  if (FLAGS_logtostderr || FLAGS_logtostdout) {
    if (FLAGS_logtostdout) {
      ColoredWriteToStdout(data_->severity_, data_->message_text_,
                           data_->num_chars_to_log_);
    } else {
      ColoredWriteToStderr(data_->severity_, data_->message_text_,
                           data_->num_chars_to_log_);
    }

    LogDestination::LogToSinks(
        data_->severity_, data_->fullname_, data_->basename_, data_->line_,
        logmsgtime_, data_->message_text_ + data_->num_prefix_chars_,
        (data_->num_chars_to_log_ - data_->num_prefix_chars_ - 1));
  } else {
    // log this message to all log files of severity <= severity_
    LogDestination::LogToAllLogfiles(data_->severity_, logmsgtime_.timestamp(),
                                     data_->message_text_,
                                     data_->num_chars_to_log_);
    LogDestination::MaybeLogToStderr(data_->severity_, data_->message_text_,
                                     data_->num_chars_to_log_,
                                     data_->num_prefix_chars_);
    LogDestination::MaybeLogToEmail(data_->severity_, data_->message_text_,
                                    data_->num_chars_to_log_);
    LogDestination::LogToSinks(
        data_->severity_, data_->fullname_, data_->basename_, data_->line_,
        logmsgtime_, data_->message_text_ + data_->num_prefix_chars_,
        (data_->num_chars_to_log_ - data_->num_prefix_chars_ - 1));
  }
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
