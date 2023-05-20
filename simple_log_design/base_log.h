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
#include <fstream>
#include <ctime>
#include <sstream>

enum LogSeverity { DEBUG, INFO, WARNING, ERROR };

class LogStream {
public:
    LogStream(const char* file, int line, const char* func, LogSeverity severity)
        : file_(file), line_(line), func_(func), level_(severity) {}

    ~LogStream() {
        std::string log_msg = formatLogMessage();
        writeToConsole(log_msg);
    }

    template <typename T>
    LogStream& operator<<(const T& value) {
        stream_ << value;
        return *this;
    }

private:
    std::string formatLogMessage() {
        std::stringstream ss;
        ss << "[" << getCurrentTime() << "] ";
        ss << "[" << getLogLevelString() << "]";
        ss << "[" << file_ << ":" << line_ << "] ";
        ss << "[" << func_ << "] ";
        ss << stream_.str();
        return ss.str();
    }

    std::string getCurrentTime() {
        std::time_t now = std::time(nullptr);
        char time_str[20];
        std::strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
        return time_str;
    }


    std::string getLogLevelString() {
      switch (level_) {
        case LogSeverity::DEBUG:
          return "DEBUG";
        case LogSeverity::INFO:
          return "INFO";
        case LogSeverity::WARNING:
          return "WARNING";
        case LogSeverity::ERROR:
          return "ERROR";
        default:
          return "UNKNOWN";
      }
    }

    void writeToConsole(const std::string& log_msg) {
        std::cout << log_msg << std::endl;
    }

private:
    const char* file_;
    int line_;
    const char* func_;
    std::stringstream stream_;
    LogSeverity level_;
};

#define LOG(level) LogStream(__FILE__, __LINE__, __FUNCTION__, level)

#endif

