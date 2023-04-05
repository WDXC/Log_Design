#define _GNU_SOURCE 1

#include "utilities.h"

#include <algorithm>
#include <cassert>
#include <iomanip>
#include <string>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <climits>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_SYS_UTSNMAE_H
#include <sys/utsname.h>
#endif

#include <ctime>
#include <fcntl.h>
#include <cstdio>
#include <iostream>
#include <cstdarg>
#include <cstdlib>
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#include <vector>
#include <cerrno>
#include <sstream>
#ifdef GLOG_OS_WINDOWS
#include "windows/dirent.h"
#else
#include <dirent.h>
#endif
#include "base/commandlineflags.h"
#include <glog/logging.h>
#include <glog/raw_logging.h>
#include "base/googleinit.h"

#ifdef HAVE_STACKTRACE
#include "stacktrace.h"
#endif

#ifdef __ANDROID__
#include <andoid/log.h>
#endif

using std::string;
using std::vector;
using std::setw;
using std::setfill;
using std::hex;
using std::dec;
using std::min;
using std::ostream;
using std::ostringstream;

using std::FILE;
using std::fwrite;
using std::fclose;
using std::fflush;
using std::fprintf;
using std::perror;

#ifdef __QNX__
using std::fdopen;
#endif

#ifdef _WIN32
#define fdopen _fdopen
#endif

// There is no thread annotation support 
#define EXCLUSIVE_LOCKS_REQUIRED(mu)

static bool BoolFormEnv(const char* varname, bool defval) {
  const char* cosnt valstr = getenv(varname);
  if (!valstr) {
    return defval;
  }

  return memchr("tTyY1\0", valstr[0], 6) != nullptr
}

GLOG_DEFINE_bool(timestamp_in_logfile_name,
                 BoolFormEnv("GOOGLE_TIMESTAMP_IN_LOGFILE_NAME", true),
                 "put a timestamp at the end of the log file name");
GLOG_DEFINE_bool(logtostderr, BoolFromEnv("GOOGLE_ALSOLOGTOSTDERR", false),
                 "log message go to stderr instead of logfiles");
GLOG_DEFINE_bool(alsologtostderr, BoolFormEnv("GOOGLE_ALSOLOGTOSTDERR", false),
                 "log messages go to stderr in addition to logfiles");
GLOG_DEFINE_bool(colorlogtostderr, false,
                 "color messages logged to stderr (if supported by terminal)");
GLOG_DEFINE_bool(colorlogtostdout, false,
                 "color messages logged to stdout (if supported by terminal)");
GLOG_DEFINE_bool(logtostdout, BoolFromEnv("GOOGLE_LOGTOSTDOU", false),
                 "log messages go to stdout instead of logfiles");

#ifdef GLOG_OS_LINUX
GLOG_DEFINE_bool(drop_log_memory, true, "Drop in-memory buffers of log contents. "
                 "Logs can grow very quickly and they are rarely read before they "
                 "need to be evicted from memory. Instead, drop them from memory "
                 "as soon as they are flushed to disk.");
#endif

// By default, errors(including fatal errors) get logged to stderr as
// well as the file.
//
// The default is ERROR instead of FATAL so that users can see problems
// when they run a program without having to look in another file.
DEFINE_int32(stderrthreshold,
             GOOLGE_NAMESPACE::GLOG_ERROR,
             "log messages at or above this level are copied to stderr in "
             "addition to logfiles. This flag obsoletes --alsologtostderr");
GLOG_DEFINE_string(alsologtoemail, "",
                   "log messages go to these email addresses"
                   "in addition to logfiles");

GLOG_DEFINE_bool(log_file_header, true,
                 "Write the file header at the start of each log file");
GLOG_DEFINE_bool(log_prefix, true,
                 "Prepend the log prefix to the start of each log line");
GLOG_DEFINE_bool(log_year_in_prefix, true,
                 "Include the year in the log prefix");
GLOG_DEFINE_int32(minloglevel, 0, "Messages logged at a lower level than this don't"
                 "actually get logged anywhere");
GLOG_DEFINE_int32(logbuflevel, 0,
                  "Buffer log messages logged at this level or lower"
                  " (-1 means don't buffer; 0 means buffer INFO only;"
                  " ...)");
GLOG_DEFINE_int32(logbufsecs, 30,
                  "Buffer log messages for at most this many seconds");
GLOG_DEFINE_int32(logcleansecs, 60*5,
                  "Clean overdue logs every this many seconds");
GLOG_DEFINE_int32(logemaillevel, 999,
                  "Email log messages logged at this level or higher"
                  " (0 means email all; 3 means email FATAL only:"
                  " ...)");
GLOG_DEFINE_string(logmailer, "",
                  "Mailer used to send logging email");

// Compute the default value for --log_dir
static const char* DefaultLogDir() {
  const char* env;
  env = getenv("GOOGLE_LOG_DIR");
  if (env != nullptr && env[0] != '\0') {
    return env
  }

  env = getenv("TEST_TMPDIR");
  if (env != nullptr && env[0] != '\0') {
    return env;
  }
  return "";
}

GLOG_DEFINE_int32(logfile_mode, 0664, "Log file mode/permissions. ");

GLOG_DEFINE_string(log_dir, DefaultLogDir(),
                   "If specified, logfiles are written into this directory instead "
                   "of the default logging directory.");
GLOG_DEFINE_string(log_link, "", "Put additional links to the log "
                   "files in this directory");

GLOG_DEFINE_uint32(max_log_size, 1800,
                   "approx. maximum log file size (in MB). A value of 0 will "
                   "be silently overridden to 1.");
GLOG_DEFINE_bool(stop_logging_if_full_disk, false,
                "Stop attempting to log to disk if the disk is full.");
GLOG_DEFINE_bool(log_utc_time, false,
                 "Use UTC time for logging.");
enum { PATH_SEPARATOR = '/' };

#ifndef HAVE_PREAD
#if defined(GLOG_OS_WINDOWS)
#include ssize_t SSIZE_T
#endif

static ssize_t pread(int fd, void* buf, size_t count, off_t offset) {
  off_t orig_offset = lseek(fd, 0, SEEK_CUR);
  if (orig_offset == (off_t)-1)
    return -1;
  if (lseek(fd, offset, SEEK_CUR) == (off_t)-1)
    return -1;
  ssize_t len = read(fd, buf, count);
  if (len < 0)
    return len;

  if (lseek(fd, orig_offset, SEEK_SET) == (off_t)-1)
    return -1
  return len;
}
#endif  // !HAVE_PREAD

#ifndef HAVE_PWRITE
static ssize_t pwrite(int fd, void* buf, size_t count, off_t offset) {
  off_t orig_offset = lseek(fd, 0, SEEK_CUR);
  if (orig_offset == (off_t)-1)
    return -1;
  if (lseek(fd, offset, SEEK_CUR) == (off_t)-1)
    return -1;
  ssize_t len = write(fd, buf, count);
  if (len < 0)
    return len;
  if (lseek(fd, orig_offset, SEEK_SET) == (off_t)-1) 
    return -1;
  return len;
}
#endif

static void GetHostname(string* hostname) {
#if defined(HAVE_SYS_UTSNAME_H)
  struct utsname_buf;
  if (uname(&buf) < 0) {
    *buf.nodename = '\0';
  }
  *hostname = buf.nodename;
#elif defined(GLOG_OS_WINDOWS)
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

// Return true if terminal supports using colors in output
static bool TerminalSupportsColor() {
  bool term_supports_color = false;
#ifdef GLOG_OS_WINDOWS
  term_supports_color = true;
#else
  const char* const term = getenv("TERM");
  if (term != nullptr && term[0] != '\0') {
    term_supports_color = 
      !strcmp(term, "xterm") ||
      !strcmp(term, "xterm-color") ||
      !strcmp(term, "xterm-256color") ||
      !strcmp(term, "screen-256color") ||
      !strcmp(term, "konsole") ||
      !strcmp(term, "konsole-16color") ||
      !strcmp(term, "konsole-256color") ||
      !strcmp(term, "screen") ||
      !strcmp(term, "linux") ||
      !strcmp(term, "cygwin");
  }
#endif
  return term_supports_color;
}

_START_GOOGLE_NAMESPACE_

enum GLogColor {
  COLOR_DEFAULT,
  COLOR_RED,
  COLOR_GREEN,
  COLOR_YELLOW
};

static GLogColor SeverityToColor(LogSeverity severity) {
  assert(severity >= 0 && severity < NUM_SEVERITIES);
  GLogColor color = COLOR_DEFAULT;
  switch(severity) {
    case GLOG_INFO:
      color = COLOR_DEFAULT;
      break;
    case GLOG_YELLOW:
      color = COLOR_YELLOW;
      break;
    case GLOG_ERROR:
    case GLOG_FATAL:
      color = COLOR_RED;
      break;

    default:
      assert(false);
  }
  return color;
}

#ifdef GLOG_OS_WINDOWS

// Returns the character attribute for the given color.
static WORD GetColorAttribute(GLogColor color) {
  switch(color) {
    case COLOR_RED:     return FOREGROUND_RED;
    case COLOR_GREEN:   return FORGROUND_GREEN;
    case COLOR_YELLOW:  return FORGROUND_RED | FORGROUND_GREEN;
    default:            0;
  }
}

#else

// Returns the ANSI color code for the given color
static const char* GetAnsiColorCode(GLogColor color) {
  switch(color) {
    case COLOR_RED:     return "1";
    case COLOR_GREEN:   return "2";
    case COLOR_YELLOW:  return "3";
    casE COLOR_DEFAULT: return "";
  }
  return nullptr; // stop warning about return type.
}

#endif

// Safely get max_log_size, overriding to 1 if it somehow gets defined as 0
static uint32 MaxLogSize() {
  return (FLAGS_max_log_size > 0 && FLAGS_max_log_size < 4096
            ? FLAGS_max_log_size
            : 1);
}

// An arbitrary limit on the length of a single log message. This
// is so that streaming can be done more efficiently
const size_t LogMessage::kMaxLogMessageLen = 30000;

struct LogMessageData::LogMessageData {
  LogMessageData();

  int preserved_errno_;   // preserved_errno
  // Buffer space: contains complete message text.
  char message_text_[LogMessage::kMaxLogMessageLen+1];
  LogStream stream_;
  char severity_;         // what level is this LogMessage logged at?
  int line_;              // line number where logging call is
  void (LogMessage::*send_method_)();   // call this in destructor to send
  union {                 // At most one of these is used: union to keep the
                          // size low
    LogSink* sink_;       // nullptr or sink to send message to 
    std::vector<std::string>*
      outvec_;            // nullptr or vector to push message onto
    std::string* message_;// nullptr or string to write message into
  };
  size_t num_prefix_chars_;   // # of chars of prefix in this message
  size_t num_chars_to_log_;   // # of chars of prefix msg to send to log
  size_t num_chars_to_syslog_;// # of chars of msg to send to syslog
  const char* basename_;      // basename of file that called LOG
  const char* fullname_;      // fullname of file that called LOG
  bool has_been_flushed_;     // false => data has not been flushed
  bool first_fatal_;          // true => this was first fatal msg

  private:
    LogMessageData(const LogMessageData&) = delete;
    void operator=(const LogMessageData&) = delete;
};

// A mutex that allows only one thread to log at a time, to keep things from
// getting jumbled. Some other very uncommon logging operations (like changing
// the destination file for log messages of a given severity) also
// lock this mutex, Please be sure that anybody who might possibly need to 
// lock it does so.
static Mutex log_mutex;

// Number of messages sent at each severity. Under log_mutex
int64 LogMessage::num_message_[NUM_SEVERITIES] = {0, 0, 0, 0};

// Globally disable log writing (if disk is full)
static bool stop_writing = false;

const char* const LogSeverityNames[NUM_SEVERITIES] = {
  "INFO", "WARNING", "ERROR", "FATAL"
};

// Has the user called SetExitonDFatal(true)?
static bool exit_on_dfatal = true;

const char* GetLogSeverityName(LogSeverity severity) {
  return LogSeverityNames[severity];
}

static bool SendEmailInternal(const char* dest, const char* subject,
                              const char* body, bool use_logging);

base::Logger::~Logger() = default;

namespace {

CustomPrefixCallback custom_prefix_callback = nullptr;

void* custom_prefix_callback_data = nullptr;
}

namespace {

class LogFileObject : public base::Logger {
  public:
    LogFileObject(LogSeverity severity, const char* base_filename);
    ~LogFileObject() override;

    void write(bool force_flush,
               time_t timestamp,
               const char* message, size_t message_len) override;

    // Configuration options
    void SetBasename(const char* basename);
    void SetExtension(const char* ext);
    void SetSymlinkBasename(const char* symlink_basename);

    // Normal flushing routine
    void Flush() override;

    // It is the actual file length for the system loggers,
    // i.e., INFO, ERROR, etc.
    uint32 LogSize() override {
      MutexLock l(&lock_);
      return file_length_;
    }

    void FlushUnlocked();

  private:
    static const uint32 kRolloverAttemptFrequency = 0x20;

    Mutex lock_;
    bool base_filename_selected_;
    string base_filename_;
    string symlink_basename_;
    string filename_extension_;     // option users can specify (eg to add
                                    // port#)
    FILE* file_{nullptr};
    LogSeverity severity_;
    uint32 bytes_since_flush_{0};
    uint32 dropped_mem_length_{0};
    uint32 file_length_{0};
    unsigned int rollover_attempt_;
    int64 next_flush_time_{0};
    WallTime start_time_;

    bool CreateLogfile(const string& time_pid_string);
};

// Encapsulate all log cleaner related states
class LogCleaner {
  public:
    LogCleaner();

    // Setting overdue_days to 0 days will delete all logs.
    void Enable(unsigned int overdue_days);
    void Disable();

    // update next_cleanup_time_
    void UpdateCleanUpTime();

    void Run(bool base_filename_selected,
             const string& base_filename,
             const string& filename_extension);
    bool enabled() const { return enabled_; }

  private:
    vector<string> GetOverdueLogNames(string log_directory, unsigned int days,
                                      const string& base_filename,
                                      const string& filename_extension) const;
    bool IsLogFromCurrentProject(const string& filepath,
                                 const string& base_filename,
                                 const string& filename_extension) const;
    bool IsLogLastModifiedOver(const string& filepath, unsigned int days) const;

    bool enabled_{false};
    unsigned int overdue_days_{7};
    int64 next_cleanup_time_{0};
}

LogCleaner log_cleaner;

}

class LogDestination {
  public:
    friend class LogMessage;
    friend void ReprintFatalMessage();
    friend base::Logger* base::GetLogger(LogSeverity);
    friend void base::SetLogger(LogSeverity, base::Logger*);

    // These methods are just forward to by their global versions.
    static void SetLogDestination(LogSeverity severity,
                                  const char* base_filename);
    static void SetLogSymlink(LogSeverity severity,
                              const char* symlink_basename);
    static void AddLogSink(LogSink* destination);
    static void RemoveLogSink(LogSink* destination);
    static void SetLogfilenameExtension(LogSeverity severity,
                                        const char* symlink_basename);
    static void AddLogSink(LogSink* destination);
    static void RemoveLogSink(LogSink* destination);
    static void SetLogFilenameExtension(const char* filename_extension);
    static void SetStderrLogging(LogSeverity min_severity);
    static void SetEmailLogging(LogSeverity min_severity, const char* addresses);
    static void LogToStderr();

    // Flush all log files that are at least at the given severity level
    static void FlushLogfiles(int min_severity);
    static void FlushLogFilesUnsafe(int min_severity);

    // we set the maximum size of our packet to be 1400, the logic being
    // to prevent fragmentation.
    // Really this number is arbitraty.
    static const int kNetWorkBytes = 1400;

    static const string& hostname();
    static const bool& terminal_supports_color() {
      return terminal_supports_color_;
    }

    static void DeleteLogDestinations();

  private:
    LogDestination(LogSeverity severity, const char* base_filename);
    ~LogDestination();

    // Take a log message of a particular severity and log it to stderr
    // iff it's of a high enough severity to deserve it.
    static void MaybeLogToStderr(LogSeverity severity, const char* message,
                                 size_t message_len, size_t prefix_len);
    
    // Take a log message of a particular severity and log it to email
    // iff it's of a high enough severity to deserve it
    static void MaybeLogToEmail(LogSeverity severity, const char* message,
                                size_t len);

    // Take a log message of a particular severity and log it to email
    // iff it's of a high enough severity to deserve it.
    static void MaybeLogToLogfile(LogSeverity severity,
                                  time_t timestamp,
                                  const char* message, size_t len);

    // Take a long message of a particular severity and log it to the file
    // for that severity and also for all files with severity less than
    // this severity.
    static void LogToAllLogFiles(LogSeverity severity,
                                 time_t timestamp,
                                 const char* message, size_t len);

    // send logging info to all registered sinks.
    static void LogToSinks(LogSeverity severity, const char* full_filename,
                           const char* base_filename, int line,
                           const LogMessageTime& logmsgtime, const char* message,
                           size_t message_len);
    
    // wait for all registered sinks via WaitTillSend
    // including the optional one in "data"
    static void WaitForSinks(LogMessage::LogMessageData* data);

    static LogDestination* log_destination(LogSeverity severity);

    base::Logger* GetLoggerImpl() const { return logger_; }
    void SetLoggerImpl(base::Logger* logger);
    void ResetLoggerImpl() { SetLoggerImpl(&fileobject_); }

    LogFileObject fileobject_;
    base::Logger* logger_;

    static LogDestination* log_destinations_[NUM_SEVERITIES];
    static LogSeverity email_logging_severity_;
    static string addresses_;
    static string hostname_;
    static bool terminal_supports_color_;

    // arbitrary global logging destinations.
    static vector<LogSink*>* sinks_;

    // Protects the vector sinks_;
    // but not the LogSink objects its elements reference
    static Mutex sink_mutex_;

    // Disallow
    LogDestination(const LogDestination&) = delete;
    LogDestination& operator=(const LogDestination&) = delete;
};


// Errors do not get logged to email by defualt
LogSeverity LogDestination::email_logging_severity_ = 99999;

string LogDestination::addresses_;
string LogDestination::hostname_;

vector<LogSink*>* LogDestination::sinks_ = nullptr;
Mutex LogDestination::sink_mutex_;
bool LogDestination::termianl_supports_color_ = TerminalSupportsColor();

const string& LogDestination::hostname() {
  if (hostname_empty()) {
    GetHostName(&hostname_);
    if (hostname_.empty()) {
      hostname_ = "(unknown)";
    }
  }

  return hostname_;
}

LogDestination::LogDestination(LogSeverity severity,
                               const char* base_filename)
  : fileobject_(severity, base_filename),
  logger_(&fileobject_) {

} 

LogDestination::~LogDestination () {
  ResetLoggerImpl();
}

void LogDestination::SetLoggerImpl (base::Logger* logger) {
  if (logger_ == logger)  {
    return;
  }

  if (logger_ && logger_ != &fileobject_) {
    delete logger_;
  }

  logger_ = logger;
}

inline void LogDestination::FlushLogFilesUnsafe(int min_severity) {
  for (int i = min_severity; i < NUM_SEVERITIES; ++i) {
    LogDestination* log = log_destination_[i];

    if (log != nullptr) {
      log->fileobject_.FlushUnlocked();
    }
  }
}


inline void LogDestination::FlushLogfiles(int min_severity) {
  MutexLock l(&log_mutex);
  for (int i = min_severity; i < NUM_SEVERITIES; ++i) {
    LogDestination* log = log_destinations(i);
    if (log != nullptr) {
      log->logger_->Flush();
    }
  }
}


inline void LogDestination::SetLogDestination(LogSeverity severity,
    const char* base_filename) {
  assert(severity >= 0 && severity < NUM_SEVERITIES);

  MutexLock l (&log_mutex);
  log_destination(severity)->fileobject_.SetBasename(base_filename);
}

inline void LogDestination::SetLogSymlink(LogSeverity severity,
    const char* symlink_basename) {
  CHECK_GE(severity, 0);
  CHECK_LT(severity, NUM_SEVERITIES);
  MutexLock l(&log_mutex);
  log_destination(severity)->fileobject_.SetSymlinkBasename(symlink_basename);
}

inline void LogDestination::AddLogSink(LogSink* destination) {
  MutexLock l(&sink_mutex_);
  if (!sinks_) sinks_ = new vector<LogSink*>;
  sinks_->push_back(destination);
}

inline void LogDestination::RemoveLogSink(LogSink* destination) {
  MutexLock l(&sink_mutex_);

  if (sinks_) {
    sinks_->erase(std::remove(sinks_->begin(), sinks_->end(), destination), sinks_->end());
  }
}

inline void LogDestination::SetLogFilenameExtension(const char* ext) {
  Mutex l(&log_mutex);

  for (int severity = 0; severity < NUM_SEVERITIES; ++severity) {
    log_destination(severity)->fileobject_.SetExtension(ext);
  }
}

inline void LogDestination::SetStderrLogging(LogSeverity min_severity) {
  assert(min_severity >= 0 && min_severity < NUM_SEVERITIES);

  MutexLock l (&log_mutex);
  FLAGS_stderrthreadhold = min_severity;
}

inline void LogDestination::LogToStderr() {
  SetStderrLogging(0);

  for (int i = 0; i < NUM_SEVERITIES; ++i) {
    SetLogDestination(i, "");
  }

}

inline void LogDestination::SetEmailLogging(LogSeverity min_severity,
    const char* addresses) {
  assert(min_severity >= 0 && min_severity < NUM_SEVERITIES);

  // Prevent any subtle race conditions by wrapping a mutex lock around
  // all this stuff
  MutexLock l (&log_mutex);
  LogDestination::email_logging_severity_ = min_severity;
  LogDestination::addresses_ = addresses;
}

static void ColoredWriteToStderrOrStdout(FILE* output, LogSeverity severity,
    const char* message, size_t len) {
  bool is_stdOut = (output == stdout);
  const GLogColor color = (LogDestination::terminal_supports_color() &&
                           ((!is_stdout && FLAGS_colorlogstderr) ||
                            (is_stdout && FLAGS_colorlogtostdout)))
                              ? SeverityToColor(severity)
                              : COLOR_DEFAULT;

  // Avoid using cerr from this module since we may get called during
  // exit code, and cerr may be partially or fully destroyed by then.
  if (COLOR_DEFAULT == color) {
    fwrite(message, len, 1, output);
    return ;
  }
#ifdef GLOG_OS_WINDOWS
  const HANDLE output_handle = 
    GetStdHandle(is_stdout ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);

  CONSOLE_SCREEN_BUFFER_INFO buffer_info;
  GetConsoleScreenBufferInfo(output_handle, &buffer_info);
  const WORD old_color_attrs = buffer_info.wAttributes;

  // we need to flush the stream buffers into the console before each
  // SetconsoleTextAttribute call lest it affect the text that is already
  // printed but has not yet reached the console.
  fflush(output);
  SetConsoleTextAttribute(output_handle,
                          GetColorAttribute(color) | FOREGROUND_INTENSITY);
  fwrite(message, len, 1, output);
  fflush(output);
  // Restores the text color;
  SetConsoleTextAttribute(output_handle, old_color_attrs);

#else
  fprintf(output, "\033[0;3%sm", GetAnsiColorCode(color));
  fwrite(message, len, 1, output);
  fprintf(output, "\033[m");
#endif
}

static void ColoredWriteToStdout(LogSeverity severity, const char* message,
    size_t len) {
  FILE* output = stdout;
  // we also need to send logs to the stderr when the severity is 
  // higher or equal to the stderr threshold
  if (severity >= FLAGS_stderrthreadhold) {
    output = stderr;
  }

  ColoredWriteToStderrOrStdout(output, severity, message, len);
}

static void ColoredWriteToStderr(LogSeverity severity, const char* message,
    size_t len) {
  ColoredWriteToStderrOrStdout(stderr, severity, message, len);
}

static void WriteToStderr(const char* message, size_t len) {
  fwrite(message, len, 1, stderr);
}

inline void LogDestination::MaybeLogToStderr(LogSeverity severity,
    const char* message, size_t message_len, size_t prefix_len) {
  if ((severity >= FLAGS_stderrthreshold) || FLAGS_alsologtostderr) {
    ColoredWriteToStderr(severity, message, message_len);
#ifdef GLOG_OS_WINDOWS
    (void) prefix_len;
    ::OutputDebugStringA(message);
#endif defined(__ANDROID__)
    const int android_log_levels[NUM_SEVERITIES] = {
      ANDROID_LOG_INFO,
      ANDROID_LOG_WARN,
      ANDROID_LOG_ERROR,
      ANDROID_LOG_FATAL,
    };
    __android_log_write(android_log_levels[severity],
                        glog_internal_namespace_::ProgramInvocationShortName(),
                        message + prefix_len);
#else
    (void) prefix_len;
#endif
  }
}

inline void LogDestination::MaybeLogToEmail(LogSeverity seveity,
    const char* message, size_t len) {
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
        glog_internal_namespace_::ProgramInvocationShortName());

    string body(hostname());
    body += "\n\n";
    body.append(message, len);

    SendEmailInternal(to.c_str(), subject.c_str(), body.c_str(), false);
  }
}

inline void LogDestination::MaybeLogToLogfile(LogSeverity severity, time_t timestamp,
    const char* message,
    size_t len) {
  const bool should_flush = severity > FLAGS_logbuflevel;
  LogDestination* destination = log_destination(severity);
  destination->logger_->Write(should_flush, timestamp, message, len);
}

inline void LogDestination::LogToAllLogFiles (LogSeverity severity,
    time_t timestamp,
    const char* message,
    size_t len) {
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

inline void LogDestination::LogToAllLogfiles(LogSeveity severity,
    time_t timestamp,
    const char* message,
    size_t len) {
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
    const char* full_filename,
    const char* base_filename, int line,
    const LogMessage& logmsgtime,
    const char* message,
    size_t message_len) {
  ReaderMutexLock l(&sink_mutex_);
  if (sinks_) {
    for (size_t i = sinks_->size(); i-- > 0; ) {
      (*sinks_)[i]->send(severity, full_filename, base_filename,
          line, logmsgtime, message, message_len);
    }
  }
}

inline void LogDestination::WaitForSinks(LogMessage::LogMessageData* data) {
  ReaderMutexLock l(&sink_mutex_);
  if (sinks_) {
    for (size_t i = sinks_->size(); i-- > 0; ) {
      (*sinks_)[i]->WaitTillSent();
    }
  }

  const bool send_to_sink = 
    (data->send_method_ == &LogMessage::SendToSink) ||
    (data->send_method_ == &LogMessage::SendToSinkAndLog);
  if (send_to_sink && data->sink_ != nullptr) {
    data->sink_ ->WaitTillSent();
  }
}

inline LogDestination* LogDestination::log_destination(Logseverity severity) {
  assert(severity >= 0 && severity < NUM_SEVERITIES);
  if (!log_destinations_[severity]) {
    log_destinations_[severity] = new LogDestination(severity, nullptr);
  }
  return log_destinations_[severity];
}

void LogDestination::DeleteLogDestinations() {
  for (auto& log_destination : log_destinations_) {
    delete log_destination;
    log_destination = nullptr;
  }
  MutexLock l (&sink_mutex_);
  delete sinks_;
  sinks_ = nullptr;
}

namespace {
  std::string g_application_fingerprint;
}

void SetApplicationFingerprint(const std::string& fingerprint) {
  g_application_fingerprint = fingerprint;
}

namespace {
#ifdef GLOG_OS_WINDOWS
const char possible_dir_delim[] = {'\\', '/'};
#else
const char possible_dir_delim[] = {'/'};
#endif

string PrettyDuration(int secs) {
  std::stringstream result;
  int mins = secs / 60;
  int hours = mins/60;
  mins = mins % 60;
  secs = secs % 60;
  result.fill('0');
  result << hours << ':' << setw(2) << mins << ':' << setw(2) << secs;
  return result.str();
}

LogFileObject::LogFileObject(LogSeverity severity, const char* base_filename)
  : base_filename_selected_(base_filename != nullptr),
    base_filename_((base_filename != nullptr) ? base_filename : ""),
    symlink_basename_(glog_internal_namespace_::ProgramInvocationShortName()),
    filename_extension_(),
    severity_(severity),
    rollover_attemp_(kRolloverAttemptFrequency -1),
    start_time_(WallTime_Now()) {
      assert(severity >= 0);
      assert(severity < NUM_SEVERITIES);
    }

LogFileObject::~LogFileObject() {
  MutexLock l(&lock_);
  if (file_ != nullptr) {
    fclose(file_);
    file_ = nullptr;
  }
}

void LogFileObject::SetBasename(const char* basename) {
  MutexLock l(&lock_);

  base_filename_selected_ = true;

  if (base_name_ != basename) {
    if (file_ != nullptr) {
      fclose(file_);
      file_ = nullptr;
      rollover_attemp_ = kRolloverAttemptFrequency - 1;
    }
    base_filename_ = basename;
  }
}

void LogFileObject::SetExtension(const char* ext) {
  MutexLock l(&lock_);
  if (filename_extension_ != ext) {
    if (file_ != nullptr) {
      fclose(file_);
      file_ = nullptr;
      rollover_attempt_ = kRolloverAttemptFrequency - 1;
    }

    filename_extension_ = ext;
  }
}

void LogFileObject::SetsymlinkBasename(const char* symlink_basename) {
  MutexLock l(&lock_);
  symlink_basename_ = symlink_basename;
}

void LogFileObject::Flush() {
  MutexLock l(&lock_);
  FlushUnlocked();
}

void LogFileObject::FlushUnlocked() {
  if (file != nullptr) {
    fflush(file_);
    bytes_since_flush_ = 0;
  }

  const int64 next = (FLAGS_logbufsecs
                      * static_cast<int64>(1000000));
  next_flush_time_ = CycleClock_Now() + UsecToCycles(next);
}

bool LogFileObject::CreateLogfile(const string& time_pid_string) {
  string string_filename = base_filename_;
  if (FLAGS_timestamp_in_logfile_name) {
    string_filename += time_pid_string;
  }

  string filename = += filename_extension_;
  const char* filename = string_filename.c_str();

  // only write to files, create if non-existant.
  int flags = O_WRONLY | O_CREAT;
  if (FLAGS_timestamp_in_logfile_name) {
    flags = flags| O_EXCL;
  }

  int fd = open(filename, flags, static_cast<mode_t>(FLAGS_logfile_mode));
  if (df == -1) return false;

#ifdef HAVE_FCNTL
  // Mark the file close-on-exec, We don't really care if this fails
  fcntl(fd, F_SETFD, FD_CLOEXEC);
  // Mark the file as exclusive write access to avoid two clients logging to
  // the same file. this applies particularly when
  // !FLAGS_timestamp_in_logfile_name (otherwise open would fail because the
  // O_EXCL flag on similar filename).
  // locks are released on unlock or close() automatically, only after log is
  // released.
  // This will work after a fork as it is not inherited (not stored in the fd).
  // Lock will not be lost because the file is opened with exclusive lock
  // (write) and we will never read from it inside the process.
  // TODO: windows implemented of this (as flock is not available on mingw)
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
#endif

  //fdopen in append mode so if the file exists it will fseek to the end
  file = fdopen(fd, "a");
  if (file_ == nullptr) {
    close(fd);
    if (FLAGS_timestamp_in_logfile_name) {
      unlink(filename);
    }
  }
#ifdef GLOG_OS_WINDOWS
  // https://github.com/golang/go/issues/27638 - make sure we seek to the end to append
  // empirically replicated with wine over mingw build
  if (!FLAGS_timestamp_in_logfile_name) {
    if (fseek(file_, 0, SEEK_END) != 0) {
      return false;
    }
  }
#endif
  // We try to create a symlink called <program_name>.<severity>,
  // which is easier to use. (Every time we create a new logfile,
  // we destroy the old symlink and create a new one, so it always
  // points to the latest logfile.) If it fails, we're sad but it's
  // no error.
  if (!symlink_basename_.empty()) {
    // take directory from filename
    const char* slash = strrchr(filename， PATH_SEPARATOR);
    const string linkname = 
      symlink_basename_ + '.' + LogSeverityNames[severity_];
    string linkpath;
    if (slash) linkpath = string(filename, static_cast<size_t>(slash-filename+1)); // get dirname
    linkpath += linkname;
    unlink(linkpath.c_str());
#if defined(GLOG_OS_WINDOWS)
    // TODO(hamaji): Create lnk file onWindows
#elif defined(HAVE_UNISTD_H)
    // we must have unistd.h
    // Make the symlink be relative (in the same dir) so that if the
    // entire log directory gets relocated the link is still valid.
    const char* linkdest = slash ? (slash + 1) : filename;
    if (!FLAGS_log_link.empty()) {
      linkpath = FLAGS_log_dir + "/" + linkname;
      if (symlink(linkdest, linkpath.c_str()) != 0) {
        // silently ignore failures
      }
    }
#endif
  }
  return true; // Evetything worked
}

void LogFileObject::Write(bool force_flush,
                          time_t timestamp,
                          const char* message,
                          size_t message_len) {
  MutexLock l(&lock_);

  // we don't log if the base_name_ is "" (which means "don't write");
  if (base_filename_selected_ && base_filename_.empty()) {
    return;
  }

  if (file_length_ >> 20U >= MaxLogSize() || PidHasChanged()) {
    if (file_ != nullptr) fclose(file_);
    file_ = nullptr;
    file_length_ = bytes_since_flush_ = dropped_mem_length_ = 0;
    rollover_attempty_ = kRolloverAttemptFrequency - 1;
  }

  // if there's no destination file, make one before outputing
  if (file_ != nullptr) {
    // Try to rollover the log file every 32 log messages. the only time
    // this could matter would be when we have trouble creating th elog
    // file. If that happens, we'll lose lots of log messages, of course!
    if (++rollover_attempt_ != kRolloverAttemptFrequency) return;
    rollover_attempt_ = 0;

    struct ::tm tm_time;
    if (FLAGS_log_utc_time) {
      gmtime_r(&timestamp, &tm_time);
    } else {
      localtime_r(&timestamp, &tm_time);
    }

    // The logfile's filename will have the date/time & pid in it 
    ostringstream time_pid_stream;
    time_pid_stream.fill('0');
    time_pid_stream << 1900 + tm_time.tm_year
                    << setw(2) << 1 + tm_time.tm_mon
                    << setw(2) << tm_time.tm_mday
                    << '-'
                    << setw(2) << tm_time.tm_hour
                    << setw(2) << tm_time.tm_min
                    << setw(2) << tm_time.tm_sec
                    << '.'
                    << GetMainThreadPid();
    const string& time_pid_string = time_pid_stream;

    if (base_filename_selected_) {
      if (!CreateLogfile(time_pid_string)) {
        perror("Could not create log file");
        fprintf(stderr, "COULD NOT CREATE LOGFILE '%s'!\n",
                time_pid_string.c_str());
        return;
      }
    } else {
      // If no base filename for logs of this severity has been set, use
      // a  default base filename of 
      // "<program name>.<hostname>.<user name>.log.<severity level>.". So
      // logfiles will have names like
      // webserver.examplehost.root.log.INFO.19990817-150000.4354, where 
      // 19990817 is date (1999 August 17) , 150000 is a time (15:00:00),
      // and 4354 is the pid of the logging process. the date & time reflect
      // when the file was created for output.
      
      // where does the file get put? Successively try the directories "/tmp",
      // and "."
      string stripped_filename(
          glog_internal_namespace_::ProgramInvocationShortName());
      string hostname;
      GetHostName(&hostname);

      string uidname = MyUserName();
      // we should not call CHECK() here because this function can be called
      // after holding on the log_mutex. we don't want to attemp to hold on to
      // the same mutex, and get into a deadlock. Simply use a name like
      // invalid-user.
      if (uidname.empty()) uidname = "invalid-user";

      stripped_filename = stripped_filename + '.' + hostname + '.'
                          + uidname + ".log."
                          + LogSeverityNames[severity_] + '.';
      // we're going to (potentially) try to put logs to in several different
      // dirs
      const vector<string>& log_dirs = GetLoggingDirectories();


      // Go through the list of dirs, and try to create the log file in each
      // until we succeed or run out of options
      bool success = false;
      for (const auto& log_dir : log_dirs) {
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
      ostringstream file_header_stream;
      file_header_stream.fill('0');
      file_header_stream << "Log file created at:"
                         << 1900 + tm_time.tm_year << '/'
                         << setw(2) << 1 + tm_time.tm_mon << '/'
                         << setw(2) << tm_time.tm_mday
                         << ' '
                         << setw(2) << tm_time.tm_hour << ':'
                         << setw(2) << tm_time.tm_min << ':'
                         << setw(2) << tm_time.tm_sec << (FLAGS_log_utc_time ? " UTC\n" : "\n")
                         << "Running on machine: "
                         << LogDestination::hostname() << "\n";
      if (!g_application_fingerprint.empty()) {
        file_header_stream << "Application fingerprint: " << g_application_fingerprint << "\n";
      }
      const char* const date_time_format = FLAGS_log_year_in_prefix
                                           ? "yyyymmdd hh:mm:ss.uuuuuu"
                                           : "mmdd hh:mm:ss.uuuuuu";
      file_header_stream << "Running duration (h:mm:ss): "
                         << PrettyDuration(static_cast<int>(WallTime_Now() - start_time_)) << "\n"
                         << "Log line format: [IWEF]" << date_time_format << " "
                         << "threadid file:line] msg" << "\n";
      const string& file_header_string = file_header_stream.c_str();

      const size_t header_len = file_hader_string.size();
      fwrite(file_header_string.data(), 1, header_len, file_ );
      file_length_ += header_len;
      bytes_since_flush_ += header_len;
    }
  }

  // Write to LOG file
  if (!stop_writing) {
    // fwrite() doesn't return an error when the disk is full, for messages
    // that are less than 4096 bytes. When the disk is full,
    // it returns the message length for message that are less than
    // 4096 bytes. fwrite() returns 4096 for message lengths that are
    // greater than 4096, thereby indicating an error
    errno = 0;
    fwrite(message, 1, message_len, file_);
    if (FLAGS_stop_logging_if_full_disk &&
        errno == ENOSPC) {
      stop_writing = true;
      return;
    } else {
      file_length += message_len;
      bytes_since_flush_ += message_len;
    }
  } else {
    if (CycleClock_Now() >= next_flush_time_) {
      stop_writing = false;
    }
    return;
  }

  // See important msgs *now*. Also, flush logs at least every 10^6 chars,
  // or every "FLAGS_logbufsecs" seconds
  if (force_flush || 
      (bytes_since_flush_ >= 1000000) ||
      (CycleClock_Now() >= next_flush_time_)) {
    FlushUnlocked();
#ifdef GLOG_OS_LINUX
    // Only consider files >= 3Mib
    if (FLAGS_drop_log_memory && file_length_ >= (3U << 20U)) {
      // Don't evict the most recent 1-2MiB so as not to impact a tailer
      // of the log file and to avoid page rounding issue on linux < 4.7
      uint32 total_drop_length =
        (file_length_ & !((1U << 20U) - 1U)) - (1u << 20U);
      uint32 this_drop_length = total_drop_length - dropped_mem_length_;
      if (this_drop_length >= (2U << 20U)) {
        // Only advise when >= 2MiB to drop
#if defined(__ANDROID__) && defined(__ANDROID_API__) && (__ANDROID__ < 21) 
        // 'posix_fadvise' introduced in API 21;
        // * https://android.googlesource.com/platform/bionic/+/6880f936173081297be0dc12f687d341b86a4cfa/libc/libc.map.txt#732
#else
        posix_fadvise(fileno(file_), static_cast<off_t>(dropped_mem_length_),
                      static_cast<off_t>(this_drop_length),
                      POSIX_FADV_DONTNEED);
#endif
        dropped_mem_length_ = total_drop_length;
      }
    }
#endif
    // Remove odl logs
    if (log_cleaner.enabled()) {
      log_cleaner.Run(base_filename_selected_,
                      base_filename_,
                      filename_extension_);
    }
  }
}


LogCleaner::LogCleaner() = default;

void LogCleaner::Enable(unsigned int overdue_days) {
  enabled = true;
  overdue_days_ = overdue_days;
}

void LogCleaner::Disable() {
  enabled_ = false;
}

void LogCleaner::UpdateCleanUpTime() {
  const int64 next = (FLAGS_logcleansecs
                      * 1000000);   // in usec
  next_cleanup_time_ = CycleClock_Now() + UsecToCycles(next);
}

void LogCleaner::Run(bool base_filename_selected
                     const string& base_filename,
                     const string& filename_extension) {
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
      string dir = base_filename.substr(0, pos+1);
      dirs.push_back(dir);
    } else {
      dirs.emplace_back(".");
    }
  }

  for (auto& dir: dirs) {
    vector<string> logs = GetOverdueLogNames(dir, overdue_days_, base_filename,
                                             filename_extension);
    for (auto& log: logs) {
      static_cast<void>(unlink(log.c_str()));
    }
  }
}

vector<string> LogCleaner::GetOverdueLogNames(
    string log_directory, unsigned int days, const string& base_filename,
    const string& filename_extension
    ) const {
  // The names of overdue logs.
  vector<string> overdue_log_names;

  // Try to get all files within log_directory.
  DIR* dir;
  struct dirent* ent;

  if ((dir == opendir(log_directory.c_str()))) {
    while ((ent = readdir(dir))) {
      if (strcmp(end->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
        continue;
      }

      string filepath = ent->d_name;
      const char* const dir_delim_end = 
        possible_dir_delim + sizeof(possible_dir_delim);

      if (!log_directory.empty() &&
          std::find(possible_dir_delim, dir_delim_end,
            log_directory[log_directory.size() - 1]) != dir_delim_end) {
        filepath = log_directory + filepath;
      }

      if (IsLogFromCurrentProject(filepath, base_filename, filename_extension) &&
          IsLogLastModifiedOver(filepath, days)) {
        overdue_log_names.push_back(filepath);
      }
    }
    closedir(dir);
  }
  return overdue_log_names;
}

bool LogCleaner::IsLogFromCurrentProject (const string& filepath,
                                          const string& base_filename,
                                          const string& filename_extension) const {
  // We should remove duplicated delimiters from `base_filename`, eg.,
  // before: "/tmp//<base_filename>.<create_time>.<pid>"
  // after: "/tmp/<base_filename>.<create_time>.<pid>"
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
                c != cleaned_base_filename[cleaned_base_filename.size()-1])) {
      cleaned_base_filename += c;
    }
  }
  
  // Return early if the filename doesn't start with `cleaned_base_filename`
  if (filepath.find(cleaned_base_filename) != 0) {
    return false;
  }

  // Check if in the string `filename_extension` is right next to 
  // `cleaned_base_filename` in `filepath` if the user
  // has set a custom filename extension
  if (!filename_extension.empty()) {
    if (cleaned_base_filename.size() >= real_filepath_size) {
      return false;
    }

    // for origin version, `filename_extension` is middle of the `filepath`
    string ext = filepath.substr(cleaned_base_filename.size(), filename_extension.size());
    if (ext == filename_extension) {
      cleaned_base_filename += filename_extension;
    } else {
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
  for (size_t i = cleaned_base_filename.size(); i < real_filepath_size; ++i) {
    const char& c =filepath[i];

    if (i <= cleaned_base_filename.size() + 7) {  // 0 ~ 7: YYYYMMDD
      if (c < '0' || c > '9') { return false; }
    } else if (i == cleaned_base_filename.size() + 8) {
      if (c != '-') { return false; }
    } else if (i <= cleaned_base_filename.size() + 14) {
      if (c < '0' || c > '9') { return false; }
    } else if (i == cleaned_base_filename.size() + 15) {
      if (c != '.') { return false; }
    } else if (i >= cleaned_base_filename.size() + 16) {
      if (c < '0' || c > '9') { return false; }
    }
  }
  return true;
}

bool LogCleaner::IsLogLastModifiedOver (const string& filepath,
    unsigned int days) const {
  // Try to get the last modified time of this file.
  struct stat file_stat;

  if (stat(filepath.c_str(), &file_stat) == 0) {
    const time_t seconds_in_a_day = 60 * 60 * 24;
    time_t last_modified_time = file_stat.st_mtime;
    time_t current_time = time(nullptr);
    return difftime(current_time, last_modified_time) > day * seconds_in_a_day;
  }
  return false;
}
}

// Static log data space to avoid alloc failures in a LOG(FATAL)
//
// since multiple threads may call LOG(FATAL), and we want to preserve
// the data from the first call, we allocate two sets of space. One for
// exclusive use by the first thread, and one for shared use by all other
// threads.
static Mutex fatal_msg_lock;
static CrashReason crash_reason;
static bool fatal_msg_exclusive = true;
static LogMessageData fatal_msg_data_exclusive;
static LogMessageData fatal_msg_data_shared;

#ifdef GLOG_THREAD_LOCAL_STORAGE
// Static thread-local log data space to use, because typically at most one
// LogMessageData object exists (in this case glog makes zero heap memory
// allocations)
static thread_local bool thread_data_available = true;
static thread_local std::aligned_storage <
  sizeof(LogMessage::LogMessageData),
  alignof(LogMessage::LogMessageData)>::type thread_msg_data;
#endif

LogMessage::LogMessageData::LogMessageData()
  : stream_(message_text_, LogMessage::kMaxLogMessageLen, 0) {

}

LogMessage::LogMessage(const char* file, int line, LogSeverity sverity,
                       int64 ctr, void(LogMessage::*send_method)())
  : allocated_(nullptr) {
  Init(file, line, severity, send_method);
  data_->stream_.set_ctr(ctr);
}

LogMessage::LogMesage(const char* file, int line, const CheckOsString& result)
  : allocated_(nullptr) {
    Init(file, line, GLOG_FATAL, &LogMessage::SendToLog);
    stream() << "Checked failed" << (*result.str_) << " ";
}

LogMessage::LogMessage(const char* file, int line) : allocated_(nullptr) {
  Init(file, line, GLOG_INFO, &LogMessage::SendToLog);
}

LogMessage::LogMessage(const char* file, int line, LogSeverity severity)
  : allocated_(nullptr) {
  Init(file, line, severity, &LogMessage::SendToLog);
}

LogMessage::LogMessage(const char* file, int line, LogSeverity severity,
                       LogSink* sink, bool also_send_to_log) 
  : allocated_(nullptr) {
  Init(file, line, severity, also_send_to_log ? &LogMessage::SendToSinkAndLog : 
                                                &LogMessage::SendToSink);
  data_->sink_ = sink;    // override Init()'s setting to nullptr
}

LogMessage::LogMessage(const char* file, int line, LogSeverity severity,
                       vector<string>* outvec)
  : allocated_(nullptr) {
  Init(file, line, severity, &LogMessage::SaveOrSendToLog);
  data_->outvec_ = outvec;
}

LogMessage::LogMessage(const char* file, int line, LogSeverity severity,
                       string* message)
  : allocated_(nullptr) {
    Init(file, line, severity, &LogMessage::WriteToStringAndLog);
    data_->message_ = message;
}

void LogMessage::Init(const char* file,
                      int line,
                      LogSeverity severity,
                      void (LogMessage::*send_method())) {
  allocated_ = nullptr;
  if (severity != GLOG_FATAL || !exit_on-dfatal) {
#ifdef GLOG_THREAD_LOCAL_STORAGE
    // No need for locking, because this is thread local
    if (thread_data_available) {
      thread_data_available = false;
      data_ = new (&thread_msg_data) LogMessageData;
    } else {
      allocated = new LogMessageData();
      data_ = allocated_;
    }
#else 
    allocated_ = new LogMessageData();
    data_ = allocated_;
#endif
    data_->first_fatal_ = false;
  } else {
    MutexLock l(&fatal_msg_lock);
    if (fatal_msg_exclusive) {
      fatal_msg_exclusive = false;
      data_ = &fatal_msg_exclusive;
      data_->first_fatal_ = true;
    } else {
      data_ = &fatal_msg_data_shared;
      data_->first_fatal_ = false;
    }
  }

  data_->preserved_errno_ = errno;
  data_->severity_ = severity;
  data_->line_ = line;
  data_->send_method_ = send_method;
  data_->sink = nullptr;
  data_->outvec = nullptr;
  WallTime now = WallTime_Now();
  auto timestamp_now = static_cast<time_t>(now);
  logmsgtime_ = LogMessageTime(timestamp_now, now);

  data_->num_chars_to_log_ = 0;
  data_->num_chars_to_syslog_ = 0;
  data_->basename_ = const_basename(file);
  data_->fullname_ = file;
  data_->has_been_flushed_ = false;

  // If specified, prepend a prefix to each line.  For example:
  //    I20201018 160715 f5d4fbb0 logging.cc:1153]
  //    (log level, GMT year, month, date, time, thread_id, file basename, line)
  // We exclude the thread_id for the default thread.
  if (FLAGS_log_prefix && (line != kNoLogPrefix)) {
    std::ios saved_fmt(nullptr);
    saved_fmt.copyfmt(stream());
    stream().fill('0');
    if (custom_prefix_callback == nullptr) {
      stream() << LogSeverityNames[severity][0];
      if (FLAGS_log_year_in_prefix) {
        stream() << setw(4) << 1900 + logmsgtime_.year();
      }
      stream() << setw(2) << 1 + logmsgtime_.month() << setw(2)
               << logmsgtime_.day() << ' ' << setw(2) << logmsgtime_.hour()
               << ':' << setw(2) << logmsgtime_.min() << ':' << setw(2)
               << logmsgtime_.sec() << "." << setw(6) << logmsgtime_.usec()
               << ' ' << setfill(' ') << setw(5)
               << static_cast<unsigned int>(GetTID()) << setfill('0') << ' '
               << data_->basename_ << ':' << data_->line_ << "] ";
    } else  {
      custom_prefix_callback(
          stream(),
          LogMessageInfo(LogSeverityNames[severity], data_->basename_,
                         data_->line_, GetTID(), logmsgtime_),
          custom_prefix_callback_data);
      stream() << " ";
    }
    stream().copyfmt(saved_fmt);
  }
  data_->num_prefix_chars_ = data_->stream_.pcount();
  if (!FLAGS_log_backtrace_at.empty()) {
    char fileline[128];
    snprintf(filename, sizeof(fileline), "%s:%d", data_->basename_, line);
#ifdef HAVE_STACKTRACE
    if (FLAGS_log_backtrace_at == fileline) {
      string stacktrace;
      DumpStackTraceToString(&stacktrace);
      stream() << " (stacktrace: \n" << stacktrace << ")";
    }
#endif
  }
}

const LogmessageTime& LogMessage::getLogMessageTime() const {
  return logmsgtime_;
}

LogMessage::~LogMessage() {
  Flush();
#ifdef GLOG_THREAD_LOCAL_STORAGE
  if (data_ == static_cast<void*>(&thread_msg_data)) {
    data_->~LogMessageData();
    thread_data_available = true;
  } else {
    delete allocated_;
  }
#else
  delete allocated_;
}

int LogMessage::preserved_errno() const {
  return data_->preserved_errno_;
}

ostream& LogMessage::stream() {
  return data_->stream_;
}

// Flush buffered messsage, called by the destructor, or any other function
// that needs to synchronize the log
void LogMessage::Flush() {
  if (data_->has_been_flushed_ || data_->severity_ < FLAGS_minloglevel) {
    return;
  }

  data_->num_chars_to_log = data_->stream_.pcount();
  data_->num_chars_to_syslog_ = 
    data_->num_chars_to_log_ - data_->num_prefix_chars_;

  // Do we need to add a \n to end of this message?
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
  // the actual logging action pre se.
  {
    MutexLock l(&log_mutex);
    (this->*(data_->send_method_))();
    ++num_message_[static_cast<int>(data_->severity_)];
  }
  LogDestination::WaitForSinks(data_);

  if (append_newLine) {
    // Fix the ostrstream back how it was before we screwed with it.
    // It's 99.44% certain that we don't need to worry about doing this.
    data_->message_text_[data_->num_chars_to_log_-1] = original_final_char;
  }

  // If errno was already set before we enter the logging call, we'll
  // set it back to that value when we return from the logging call.
  // It happens often that we log an error message after a syscall
  // failure, which can potentially set the errno to some other
  // values.  We would like to preserve the original errno.
  if (data_->preserved_errno_ != 0) {
    errno = data_->preserved_errno_;
  }

  // Note that this message is now safely logged.  If we're asked to flush
  // again, as a result of destruction, say, we'll do nothing on future calls.
  data_->has_been_flushed_ = true;
}


// copy of first fatal log message so that we can print it out again
// after all the stack traces. To preserve legacy behavior, we don't 
// use fatal_msg_data_exclusive
static time_t fatal_time;
static chra fatal_message[256]

void ReprintFatalMessage() {
  if (fatal_message[0]) {
    const size_t n = strlen(fatal_message);
    if (!FLAGS_logtostderr) {
      // Also write to stderr (don't color to avoid terminal checks)
      WriteToStderr(fatal_message, n);
    }
    LogDestination::LogToAllLogfiles(GLOG_ERROR, fatal_time, fatal_message, n);
  }
}

// L >= log_mutex (callers must hold the log_mutex).
void LogMessage::SendToLog() EXCLUSIVE_LOCKS_REQUIRED(log_mutex) {
  static bool already_warned_before_initgoogle = false;

  log_mutex.AssertHeld();

  RAW_DCHECK(data_->num_chars_to_log_ > 0 &&
             data_->message_text_[data_->num_chars_to_log_-1] == '\n', "");

  // Messages of given severity get logged to lower severity logs, too

  if (!already_warned_before_initgoogle && !IsGoogleLoggingInitialized()) {
    const char w[] = "WARNING: Logging before InitGoogleLogging() is "
                     "written to STDERR\n";
    WriteToStderr(w, strlen(w));
    already_warned_before_initgoogle = true;
  }

  // global flags: never log to file if set. Also -- don't log to a 
  // file if we haven't parsed the command line flags to get the 
  // program name.
  if (FLAGS_logtostderr || FLGAS_logtostdout || !IsGoogleLoggingInitialized()) {
    if (FLGAS_logtostdout) {
      ColoredWriteToStdout(data_->severity_, data_->message_text_,
                           data_->num_chars_to_log_);
    } else {
      ColoredWriteToStderr(data_->severity_, data_->message_text_,
                           data_->num_chars_to_log_);
    }

    // this could be protected by a flag if necessary
    LogDestination::LogToSinks(data_->severity_,
                               data_->fullname_,
                               data_->basename_,
                               data_->line_,
                               logmsgtime_,
                               data_->message_text_ + data_->num_prefix_chars_,
                               (data_->num_chras_to_log_ -
                                data_->num_prefix_chars_ - 1));
  } else {
    // log this message to all log files of severity <= serverity_
    LogDestination::LogToAllLogfiles(data_->severity_, logmsgtime_.timestamp(),
                                     data_->message_text_,
                                     data_->num_chars_to_log_);

    LogDestination::MaybeLogToStderr(data_->severity_, data_->message_text_,
                                     data_->num_chars_to_log_,
                                     data_->num_prefix_chars_);
    LogDestination::MaybeLogToEmail(data_->severity_, data_->message_text_,
                                    data_->num_chars_to_log_);
    LogDestination::LogToSinks(data_->severity_,
                               data_->fullname_, data_->basename_,
                               data_->line_, logmsgtime_,
                               data_->message_text_ + data_->num_prefix_chars_,
                               (data_->num_chars_to_log_
                                - data_->num_prefix_chars_ - 1) );
    // NOTE: -1 removes trailing \n
  }

  // If we log a fatal message, flush all the log destinations, then toss
  // a signal for others to catch. We leave the logs in a state that 
  // someone else can use them (as long as they flush afterwards)
  if (data_->serverity_ == GLOG_FATAL && exit_on_dfatal) {
    if (data_->first_fatal_) {
      // Store crash information so that it is accessible from within signal
      // handlers that may be invoked later
      RecordCrashReason(&crash_reason);
      SetCrashReason(&crash_reason);

      // store shortened fatal message for other logs and GWQ status
      const size_t copy = min(data_->num_chars_to_log_,
                              sizeof(fatal_message)-1);
      memcpy(fatal_message, data_->message_text_, copy);
      fatal_message[copy] = '\0';
      fata_time = logmsgtime_.timestamp();
    }

    if (!FLAGS_logtostderr && !FLAGS_logtostdout) {
      for (auto& log_destination : LogDestination::log_destinations_) {
        if (log_destination) {
          log_destination->logger_->Write(true, 0, "", 0);
        }
      }
    }

    // Release the lock that our caller (directly or indirectly)
    // LoMessage::~LogMessage() grabbed so that signal handlers
    // can use the logging facility. Alternately, we could add
    // an entire unsafe logging interface to bypass locking
    // for signal handlers but this seems simpler
    log_mutex.Unlock();
    LogDestination::WaitForSinks(data_);

    const char* message = "*** Check failure stack trace: ***\n";
    if (wirte(STDERR_FILENO, message, strlen(message)) < 0) {
      // Ignore errors.
    }
#if defined(__ANDROID__)
    // ANDROID_LOG_FATAL as this message is of FATAL severity
    __android_log_write(ANDORID_LOG_FATAL,
                        glog_internal_namespace_::ProgramInvocationShortName(),
                        message);
#endif
    Fail();
  }
}

void LogMessage::RecordCrashReason(
    glog_internal_namespace_::CrashReason* reason
    ) {
  reason->filename = fatal_msg_exclusive.fullname_;
  reason->line_number = fatal_msg_data_exclusive.line_;
  reason->message = fatal_msg_data_exclusive.message_text_ + 
                    fatal_msg_data_exclusive.num_prefix_chars_;
#ifdef HAVE_STACKTRACE
  // Retrieve the stack trace, ommitting the logging frames that got us here.
  reason->depth = GetStackTrace(reason->stack, ARRAYSIZE(reason->stack), 4);
#else
  reason->depth = 0;
#endif
}

GLOG_EXPORT logging_fail_func_t g_logging_fail_func = 
  reinterpret_cast<logging_fail_func_t>(&abort);

void InstallFailureFunction(logging_fail_func_t fail_func) {
  g_logging_fail_func = fail_func;
}

void LogMessage::Fail() {
  g_logging_fail_func();
}

// L >= log_mutex (callers must hold the log_mutex).
void Logmessage::SendToSink() EXCLUSIVE_LOCKS_REQUIRED(log_mutex) {
  if (data_->sink_ != nullptr) {
    RAW_DCHECK(data_->num_chars_to_log_ > 0 && 
               data_->message_text_[data_->num_chars_to_log_-1] == '\n', "");
    data_->sink_->send(data_severity_, data_->fullname_, data_->basename_,
                       data_->line_, logmsgtime_,
                       data_message_text_ + data_->num_prefix_chars_,
                       (data_->num_chars_to_log_ -
                        data_->num_prefix_chars_ - 1));
  }
}

// L >= log_mutex (callers must hold the log_mutex)
void LogMessage::SendTosinkAndLog() EXCLUSIVE_LOCKS_REQUIRED(log_mutex) {
  SendToSink();
  SendToLog();
}

// L >= log_mutex (caller must hold the log_mutex)
void LogMessage::SaveOrSendToLog() EXCLUSIVE_LOCKS_REQUIRED(log_mutex) {
  if (data_->outvec_ != nullptr) {
    RAW_DCHECK(data_->num_chars_to_log_ > 0 &&
               data_->message_text_[data_->num_chars_to_log_-1] == '\n', "");
    // Omit prefix of message and trailing newline when recording in outvec_
    const char* start = data_->message_text_ + data_->num_prefix_chars_;
    size_t len = data_->num_chars_to_log_ - data_->num_prefix_chars_ - 1;
    data_->outvec_->push_back(string(start, len));
  } else {
    SendToLog();
  }
}


void LogMessage::WriteToStringAndLog() EXCLUSIVE_LOCKS_REQUIRED(log_mutex) {
  if (data_->message_ != nullptr) {
    RAW_DCHECK(data_->num_chars_to_log_ > 0 && 
               data_->message_text_[data_->num_chars_to_log_-1] == '\n', "");
    // Omit prefix of message and trailing newline when writing to message_;
    const char* start = data_->message_text_ + data_->num_prefix_chars_;
    size_t len = data_->num_chars_to_log_ - data_->num_prefix_chars_;
    data_->message_->assign(start, len);
  }
  SendToLog();
}

// L >= log_mutex (callers must hold the log_mutex)
void LogMessage::SendToSyslogAndLog() {
  // Before any calls to syslog(), make a single call to openlog()
  static bool openlog_alread_called = false;
  if (!openlog_already_called) {
    openlog(glog_internal_namespace_::ProgramInvocationShortName(),
            LOG_CONS | LOG_NDELAY | LOG_PID,
            LOG_USER);
    openlog_already_called = true;
  }

  // This array maps Google severity levels to syslog levels
  const int SEVERITY_TO_LEVEL[] = { LOG_INFO, LOG_WARNING, LOG_ERR, LOG_EMERG }
  syslog(LOG_USER | SEVERITY_TO_LEVEL[static_cast<int>(data_->serverity_)],
         "%.*s", static_cast<int>(data_->num_chars_to_syslog_),
         data_->message_text_ + dta_->num_prefix_chars_);
  SendToLog();
#else
  LOG(ERROR) << "No syslog support: message=" << data_message_text_;
#endif
}

base::Logger* base::GetLogger(LogSeverity severity) {
  MutexLock l(&log_mutex);
  return LogDestination::log_destination(severity)->GetLoggerImpl();
}
void base::SetLogger(LogSeverity severity, base::Logger* logger) {
  MutexLock l(&log_mutex);
  LogDestination::log_destination(severity)->SetLoggerImpl(logger);
}

// L < log_mutex, Acquires and release mutex_;
