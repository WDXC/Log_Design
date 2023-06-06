// At the first, the log need some basic ability
// [] basic record info ability
// [] different log level
// [] offer speify recording style
// [] Write the log info to file
// [] Each line should have these attribute: 1. Date 2. time 3. timestamp 4.
// filename 5. line_number
// [] Could confirm thread safe in multhread envrionment

#ifndef BASE_LOG_H_
#define BASE_LOG_H_

#include "Type.h"
#include <ctime>
#include <vector>

class LogStreamBuf : public std::streambuf {
public:
  LogStreamBuf(char *buf, int len) { setp(buf, buf + len - 2); }

  int_type overflow(int_type ch) { return ch; }

  // Legacy effectively ignores overflow
  size_t pcount() const { return static_cast<size_t>(pptr() - pbase()); }
  char *pbase() const { return std::streambuf::pbase(); }
};

struct LogMessageTime {
  LogMessageTime();
  LogMessageTime(std::tm t);
  LogMessageTime(std::time_t timestamp, WallTime now);

  //  struct tm {
  //      int tm_sec;    /* Seconds (0-60) */
  //      int tm_min;    /* Minutes (0-59) */
  //      int tm_hour;   /* Hours (0-23) */
  //      int tm_mday;   /* Day of the month (1-31) */
  //      int tm_mon;    /* Month (0-11) */
  //      int tm_year;   /* Year - 1900 */
  //      int tm_wday;   /* Day of the week (0-6, Sunday = 0) */
  //      int tm_yday;   /* Day in the year (0-365, 1 Jan = 0) */
  //      int tm_isdst;  /* Daylight saving time */
  //  };

  const time_t &timestamp() const { return timestamp_; }
  const int &sec() const { return time_struct_.tm_sec; }
  const int32_t &usec() const { return usecs_; }
  const int &min() const { return time_struct_.tm_min; }
  const int &hour() const { return time_struct_.tm_hour; }
  const int &day() const { return time_struct_.tm_mday; }
  const int &month() const { return time_struct_.tm_mon; }
  const int &year() const { return time_struct_.tm_year; }
  const int &dayOfWeek() const { return time_struct_.tm_wday; }
  const int &dayInYear() const { return time_struct_.tm_yday; }
  const int &dst() const { return time_struct_.tm_isdst; }
  const long int &gmtoff() const { return gmtoffset_; }
  const std::tm &tm() const { return time_struct_; }

private:
  void init(const std::tm &t, std::time_t timestamp, WallTime now);
  std::tm time_struct_; // Time of creation of LogMessage
  time_t timestamp_;
  int32_t usecs_;
  long int gmtoffset_;

  void CalcGmtOffset();
};

class QLog {

public:
  enum { kNoLogPrefix = -1 };

  class LogStream : public std::ostream {
  public:
    LogStream(char *buf, int len, int64 ctr)
        : std::ostream(NULL), streambuf_(buf, len), ctr_(ctr), self_(this) {
      rdbuf(&streambuf_);
    }
    int64 ctr() const { return ctr_; }
    void set_ctr(int64 ctr) { ctr_ = ctr; }
    LogStream *self() const { return self_; }

    // Legacy std::streambuf methods.
    size_t pcount() const { return streambuf_.pcount(); }
    char *pbase() const { return streambuf_.pbase(); }
    char *str() const { return pbase(); }

  private:
    LogStream(const LogStream &);
    LogStream &operator=(const LogStream &);
    LogStreamBuf streambuf_;
    int64 ctr_;
    LogStream *self_;
  };

public:
  typedef void (QLog::*SendMethod)();
  QLog(const char *file, int line);
  ~QLog();

  void Flush();

  void SendToLog();

  std::ostream &stream();

  const LogMessageTime &getLogMessageTime() const;

public:
  static const size_t kMaxLogMessageLen;
  struct LogMessageData;

private:
  void Init(const char *file, int line, LogSeverity severity,
            void (QLog::*send_method)());

private:
  static int64 num_messages_[NUM_SEVERITIES];

  LogMessageData *allocated_;
  LogMessageData *data_;
  LogMessageTime logmsgtime_;

  void operator=(const QLog &);
};

class Logger {
public:
    virtual ~Logger();

    // Writes "message[0, message_len-1]" corresponding to an event that
    // occurred at "timestamp". If 'force_flush' is true, the log file 
    // is flushed immediately.
    //
    // The input message has already been formatted as deemed
    // appropriate by the higher level level logging facility. For example,
    // textual log messages already contain timestamps, and the
    // file: linenumber header
    virtual void Write(bool force_flush,
                       time_t timestamp,
                       const char* message,
                       size_t message_len) = 0;
    // Flush any buffered messages
    virtual void Flush() = 0;

    // Get the current LOG file size.
    // The returned value is approximate since some
    // logged data may not have been flushed to disk yet
    virtual uint32 LogSize() = 0;
};

Logger* GetLogger(LogSeverity level);

void SetLogger(LogSeverity level, Logger* logger);

class LogSink {
public:
  virtual ~LogSink();
  virtual void send(LogSeverity severity, const char *full_filename,
                    const char *base_filename, int line,
                    const LogMessageTime &logmsgtime, const char *message,
                    size_t message_len);
  virtual void send(LogSeverity severity, const char *full_filename,
                    const char *base_filename, int line, const std::tm *t,
                    const char *message, size_t message_len);

  virtual void WaitTillSent();
  static std::string ToString(LogSeverity severity, const char *file, int line,
                              const QLog &logmsgtime, const char *message,
                              size_t message_len);
};

// Add or remove a LogSink as a consumer of logging data.  Thread-safe.
void AddLogSink(LogSink *destination);
void RemoveLogSink(LogSink *destination);

//
// Specify an "extension" added to the filename specified via
// SetLogDestination.  This applies to all severity levels.  It's
// often used to append the port we're listening on to the logfile
// name.  Thread-safe.
//
void SetLogFilenameExtension(const char *filename_extension);

//
// Make it so that all log messages of at least a particular severity
// are logged to stderr (in addition to logging to the usual log
// file(s)).  Thread-safe.
//
void SetStderrLogging(LogSeverity min_severity);

//
// Make it so that all log messages go only to stderr.  Thread-safe.
//
void LogToStderr();

//
// Make it so that all log messages of at least a particular severity are
// logged via email to a list of addresses (in addition to logging to the
// usual log file(s)).  The list of addresses is just a string containing
// the email addresses to send to (separated by spaces, say).  Thread-safe.
//
void SetEmailLogging(LogSeverity min_severity, const char *addresses);

// A simple function that sends email. dest is a comma-separated
// list of addresses. Thread-safe
bool SendEmail(const char* dest, const char* subject,
        const char* body);

const std::vector<std::string>& GetLoggingDirectories();

// Force tests only: Clear the internal [cached] list of logging directories to 
// force a refresh the next time GetLoggingDirectories is called.
// Thread-hostile
void TestOnly_ClearLoggingDirectoriesList();

// Returns a set of existing temporary directories, which will be a 
// subset of the directories returned by GetLoggingDirectories().
// Thread-safe
void GetExistingTempDirectories(std::vector<std::string>* list);

// Print any fatal message again -- useful to call from signal handler
// so that the last thing in the output is the fatal message.
// Thread-hostile, but a race is unlikely
void ReprintFatalMessage();

// Truncate a log file that may be the append-only output of multiple
// processes and hence can't simply be renamed/reopened (typically a 
// stdout/stderr). If the file "path" is > "limit" bytes, copy the 
// last "keep" bytes to offset 0 and truncate the reset. Since we could 
// be racing with other writers, this approach has the potential to 
// lose very small amounts of data.For security, only follow symlinks
// if the path is /proc/self/fd/*
void TruncateLogFile(const char* path, uint64 limit, uint64 keep);

// Truncate stdout and stderr if they are over the value specified by 
// --max_log_size; keep the final 1MB. This function has the same
// race condition as TruncateLogFile
void TruncateStdoutStderr();

// Return the string representation of the provided LogSeverity level.
// Thread-safe
const char* GetLogSeverityName(LogSeverity severity);


#define LOG(severity) QLog(__FILE__, __LINE__).stream()

#endif
