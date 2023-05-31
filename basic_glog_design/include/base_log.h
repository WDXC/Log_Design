// At the first, the log need some basic ability
// [] basic record info ability
// [] different log level
// [] offer speify recording style
// [] Write the log info to file
// [] Each line should have these attribute: 1. Date 2. time 3. timestamp 4. filename 5. line_number
// [] Could confirm thread safe in multhread envrionment

#ifndef BASE_LOG_H_
#define BASE_LOG_H_


#include <ctime>
#include "Type.h"


class LogStreamBuf : public std::streambuf {
  public:
    LogStreamBuf(char* buf, int len) {
      setp(buf, buf+len-2);
    }

    int_type overflow(int_type ch) {
      return ch;
    }

    // Legacy effectively ignores overflow
    size_t pcount() const { return static_cast<size_t>(pptr() - pbase()); }
    char* pbase() const { return std::streambuf::pbase(); }
};

class LogSink {
// If a non-NULL sink pointer is given, we push this message to that sink
// For LOG_TO_SINK we then do normal LOG(severity) logging as well.
// This is useful for capturing messages and passing/storing them
// somewhere more specific than the global log of the process.
// Argument types:
//  Logsinks* sink;
//  LogSeverity severity;
// The cast is to disambiguate NULL arguments

#define LOG_TO_SINK(sink, severity) \
  @ac_google_namespace@::LogMessage(                                    \
      __FILE__, __LINE__,                                               \
      @ac_google_namespace@::GLOG_ ## severity,                         \
      static_cast<@ac_google_namespace@::LogSink*>(sink), true).stream()
#define LOG_TO_SINK_BUT_NOT_TO_LOGFILE(sink, severity)                  \
  @ac_google_namespace@::LogMessage(                                    \
      __FILE__, __LINE__,                                               \
      @ac_google_namespace@::GLOG_ ## severity,                         \
      static_cast<@ac_google_namespace@::LogSink*>(sink), false).stream()

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

  const time_t& timestamp() const { return timestamp_; }
  const int& sec() const { return time_struct_.tm_sec; }
  const int32_t& usec() const { return usecs_; }
  const int& min() const { return time_struct_.tm_min; }
  const int& hour() const { return time_struct_.tm_hour; }
  const int& day() const { return time_struct_.tm_mday; }
  const int& month() const { return time_struct_.tm_mon; }
  const int& year() const { return time_struct_.tm_year; }
  const int& dayOfWeek() const { return time_struct_.tm_wday; }
  const int& dayInYear() const { return time_struct_.tm_yday; }
  const int& dst() const { return time_struct_.tm_isdst; }
  const long int& gmtoff() const { return gmtoffset_; }
  const std::tm& tm() const { return time_struct_; }

  private:
    void init(const std::tm& t, std::time_t timestamp, WallTime now);
    std::tm time_struct_;   // Time of creation of LogMessage
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
        LogStream(char* buf, int len, int64 ctr)
          : std::ostream(NULL),
            streambuf_(buf, len),
            ctr_(ctr),
            self_(this) {
              rdbuf(&streambuf_);
            }
        int64 ctr() const { return ctr_; }
        void set_ctr(int64 ctr) { ctr_ = ctr; }
        LogStream* self() const { return self_; }
        
        // Legacy std::streambuf methods.
        size_t pcount() const { return streambuf_.pcount(); }
        char* pbase() const { return streambuf_.pbase(); }
        char* str() const { return pbase(); }

      private:
        LogStream(const LogStream&);
        LogStream& operator=(const LogStream&);
        LogStreamBuf streambuf_;
        int64 ctr_;
        LogStream* self_;
    };

  public:

    typedef void (QLog::*SendMethod)();
    QLog(const char* file, int line);
    ~QLog();

    void Flush();
    
    void SendToLog();

    std::ostream& stream();

    const LogMessageTime& getLogMessageTime() const;

  public:
    static const size_t kMaxLogMessageLen;
    struct LogMessageData;

  private:
    void Init(const char* file, int line, LogSeverity severity, void (QLog::*send_method)());

  private:
    static int64 num_messages_[NUM_SEVERITIES];

    LogMessageData* allocated_;
    LogMessageData* data_;
    LogMessageTime logmsgtime_;

    void operator=(const QLog&);
};


#define LOG(severity) QLog(__FILE__, __LINE__).stream()

#endif

