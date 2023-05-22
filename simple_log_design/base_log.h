// At the first, the log need some basic ability
// [] basic record info ability
// [] different log level
// [] offer speify recording style
// [] Write the log info to file
// [] Each line should have these attribute: 1. Date 2. time 3. timestamp 4. filename 5. line_number
// [] Could confirm thread safe in multhread envrionment

#ifndef BASE_LOG_H_
#define BASE_LOG_H_

#include <iostream>
#include <ctime>


#define DECLARE_VARIABLE(type, shorttype, name, tn)                     \
  namespace fL##shorttype {                                             \
    extern type FLAGS_##name;                      \
  }                                                                     \
  using fL##shorttype::FLAGS_##name

// bool specialization
#define DECLARE_bool(name) \
  DECLARE_VARIABLE(bool, B, name, bool)

DECLARE_bool(log_utc_time);

using LogSeverity = int;

const int GLOG_INFO = 0, GLOG_WARNING = 1, GLOG_ERROR = 2, GLOG_FATAL = 3,
  NUM_SEVERITIES = 4;

typedef std::uint64_t int64;
typedef double WallTime;

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

class LogSink {};


struct LogMessageTime {
  LogMessageTime();
  LogMessageTime(std::tm t);
  LogMessageTime(std::time_t timestamp, WallTime now);

  const time_t& timestamp() const { return timestamp_; }
  const int& sec() const { return time_struct_.tm_sec; }

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
    void Init(const char* file, int line, LogSeverity severity);

  private:
    static int64 num_messages_[NUM_SEVERITIES];

    LogMessageData* allocated_;
    LogMessageData* data_;
    LogMessageTime logmsgtime_;

    QLog(const QLog&);
    void operator=(const QLog&);
};


#endif

