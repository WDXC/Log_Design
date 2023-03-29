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

