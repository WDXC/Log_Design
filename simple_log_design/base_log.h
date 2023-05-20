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
#include <cstdio>
#include <string>

using std::string;

#define MAX_LOG_INFO 65535
const int DEBUG = 0, INFO = 1, WARNING = 2, ERROR = 3;

class QLog {
  public:
    std::ostream& stream();
    void WriteLog(const char* file, int line, string level, ...);

  private:
    QLog() : buffer() {}
    static QLog log_instance;
    char buffer[MAX_LOG_INFO];
};

#define LOG(level) LOG_ ## level


#endif
