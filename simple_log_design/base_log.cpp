#include "base_log.h"
#include <vector>

const size_t QLog::kMaxLogMessageLen = 30000;

struct QLog::LogMessageData {
  LogMessageData();

  char message_text_[QLog::kMaxLogMessageLen+1];
  LogStream stream_;
  char severity_;
  int line_;
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

void LogMessageTime::CalcGmtOffset () {
  std::tm gmt_struct;
  int isDst = 0;
  if (FLAGS_log_utc_time) {
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
