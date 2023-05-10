# 单元测试分析(logging_unittest)
argv[0] 会默认带有函数的当前程序的地址信息
即我运行 ./logging_unittest 那么 argv[0]的参数是 "/root/mine/Project/glog/build/logging_unittest"

g_new_hook 是一个函数指针，由google test中所提供，其定义如下:
```
void(*g_new_hook)() = nullptr;
亦可用如下方式进行定义
using g_new_hook = void(*)();
g_new_hook = nullptr;
```

第一个测试用例:
```
// TestSuiteName 测试组名
// TestName 指定测试函数名
TEST(TestSuiteName, TestName) {}

static void NoAllocNewHook() {
  LOG(FATAL) << "unexpected new";
}

struct NewHook {
  NewHook() {
    // decalre in googletest 
    // g_new_hook is a function pointer
    g_new_hook = &NoAllocNewHook;
  }
  ~NewHook() { g_new_hook = nullptr; }
};

TEST(DeathNoAllocNewHook, logging) {
  // tests that NewHook used below works
  NewHook new_hook;
  ASSERT_DEATH({
    new int;
  }, "specify 23");
}
```

首先执行这个测试的目的是: 
1. 测试在该机器下是否有内存去执行程序
2. 测试googletest的可用性

LOG(INFO) -> COMPACT_GOOGLE_LOG_FATAL -> LogMessageFatal -> ~LogMessageFatal ->
LogMessage::Flush() -> LogMessage::Fail() -> 程序崩溃 -> ASSERT_DEATH 吞下
->继续执行TEST
只有明确知道程序一定会崩溃时才可以使用LOG(FATAL)，因为使用FATAL同样会导致程序终止
这个TEST并没有触发这个崩溃是因为，这个崩溃被包括在了ASSERT_DEATH(),只有LOG(FATAL)崩溃才能让ASSERT_DEATH不会抛出GoogleTest测试异常,准确来说，就是LOG(FATAL)被ASSERT_DEATH吞掉了,但常规情况下，仍是只有在特殊情况下才可以使用LOG(FATAL);

第二个单元测试:
```c++

// Helper macro for string comparisons.
// Don't use this macro directly in your code, use CHECK_STREQ et al below.
#define CHECK_STROP(func, op, expected, s1, s2) \
  while (@ac_google_namespace@::CheckOpString _result = \
         @ac_google_namespace@::Check##func##expected##Impl((s1), (s2), \
                                     #s1 " " #op " " #s2)) \
    LOG(FATAL) << *_result.str_


// String (char*) equality/inequality checks.
// CASE versions are case-insensitive.
//
// Note that "s1" and "s2" may be temporary strings which are destroyed
// by the compiler at the end of the current "full expression"
// (e.g. CHECK_STREQ(Foo().c_str(), Bar().c_str())).
#define CHECK_STREQ(s1, s2) CHECK_STROP(strcmp, ==, true, s1, s2)


TEST(DeathSTREQ, logging) {
  ASSERT_DEATH(CHECK_STREQ(nullptr, "this"), "");
  ASSERT_DEATH(CHECK_STREQ("this", "siht"), "");
  ASSERT_DEATH(CHECK_STRCASEEQ(nullptr, "siht"), "");
  ASSERT_DEATH(CHECK_STRCASEEQ("this", "siht"), "");
  ASSERT_DEATH(CHECK_STRNE(nullptr, nullptr), "");
  ASSERT_DEATH(CHECK_STRNE("this", "this"), "");
  ASSERT_DEATH(CHECK_STREQ((string("a")+"b").c_str(), "abc"), "");
}
```

这里有一个很有意思的现象，就是观察日志，我们可以看到后面的ASSERT_DEATH的日志总是被添加到后面，而不是单独的一个打印，可以暂时思考一下？
日志信息如下:
```
F20230424 13:28:15.469147 2128115 logging_unittest.cc:355] unexpected new
*** Check failure stack trace: ***
F00000000 00:00:00.000000 2128115 logging_unittest.cc:526] RAW: Check false failed: failure 1
F00000000 00:00:00.000000 2128115 logging_unittest.cc:528] RAW: Check 1 == 2 failed: failure 2
F20230424 13:28:15.469203 2128115 logging_unittest.cc:680] CHECK_STREQ failed: nullptr == "this" ( vs. this)
*** Check failure stack trace: ***
F20230424 13:28:15.469203 2128115 logging_unittest.cc:680] CHECK_STREQ failed: nullptr == "this" ( vs. this)
F20230424 13:28:15.469218 2128115 logging_unittest.cc:681] CHECK_STREQ failed: "this" == "siht" (this vs. siht)
*** Check failure stack trace: ***
F20230424 13:28:15.469203 2128115 logging_unittest.cc:680] CHECK_STREQ failed: nullptr == "this" ( vs. this)
F20230424 13:28:15.469218 2128115 logging_unittest.cc:681] CHECK_STREQ failed: "this" == "siht" (this vs. siht)
F20230424 13:28:15.469231 2128115 logging_unittest.cc:682] CHECK_STRCASEEQ failed: nullptr == "siht" ( vs. siht)
*** Check failure stack trace: ***
F20230424 13:28:15.469203 2128115 logging_unittest.cc:680] CHECK_STREQ failed: nullptr == "this" ( vs. this)
F20230424 13:28:15.469218 2128115 logging_unittest.cc:681] CHECK_STREQ failed: "this" == "siht" (this vs. siht)
F20230424 13:28:15.469231 2128115 logging_unittest.cc:682] CHECK_STRCASEEQ failed: nullptr == "siht" ( vs. siht)
F20230424 13:28:15.469252 2128115 logging_unittest.cc:683] CHECK_STRCASEEQ failed: "this" == "siht" (this vs. siht)
*** Check failure stack trace: ***
F20230424 13:28:15.469203 2128115 logging_unittest.cc:680] CHECK_STREQ failed: nullptr == "this" ( vs. this)
F20230424 13:28:15.469218 2128115 logging_unittest.cc:681] CHECK_STREQ failed: "this" == "siht" (this vs. siht)
F20230424 13:28:15.469231 2128115 logging_unittest.cc:682] CHECK_STRCASEEQ failed: nullptr == "siht" ( vs. siht)
F20230424 13:28:15.469252 2128115 logging_unittest.cc:683] CHECK_STRCASEEQ failed: "this" == "siht" (this vs. siht)
F20230424 13:28:15.469266 2128115 logging_unittest.cc:684] CHECK_STRNE failed: nullptr != nullptr ( vs. )
*** Check failure stack trace: ***
F20230424 13:28:15.469203 2128115 logging_unittest.cc:680] CHECK_STREQ failed: nullptr == "this" ( vs. this)
F20230424 13:28:15.469218 2128115 logging_unittest.cc:681] CHECK_STREQ failed: "this" == "siht" (this vs. siht)
F20230424 13:28:15.469231 2128115 logging_unittest.cc:682] CHECK_STRCASEEQ failed: nullptr == "siht" ( vs. siht)
F20230424 13:28:15.469252 2128115 logging_unittest.cc:683] CHECK_STRCASEEQ failed: "this" == "siht" (this vs. siht)
F20230424 13:28:15.469266 2128115 logging_unittest.cc:684] CHECK_STRNE failed: nullptr != nullptr ( vs. )
F20230424 13:28:15.469280 2128115 logging_unittest.cc:685] CHECK_STRNE failed: "this" != "this" (this vs. this)
*** Check failure stack trace: ***
F20230424 13:28:15.469203 2128115 logging_unittest.cc:680] CHECK_STREQ failed: nullptr == "this" ( vs. this)
F20230424 13:28:15.469218 2128115 logging_unittest.cc:681] CHECK_STREQ failed: "this" == "siht" (this vs. siht)
F20230424 13:28:15.469231 2128115 logging_unittest.cc:682] CHECK_STRCASEEQ failed: nullptr == "siht" ( vs. siht)
F20230424 13:28:15.469252 2128115 logging_unittest.cc:683] CHECK_STRCASEEQ failed: "this" == "siht" (this vs. siht)
F20230424 13:28:15.469266 2128115 logging_unittest.cc:684] CHECK_STRNE failed: nullptr != nullptr ( vs. )
F20230424 13:28:15.469280 2128115 logging_unittest.cc:685] CHECK_STRNE failed: "this" != "this" (this vs. this)
F20230424 13:28:15.469293 2128115 logging_unittest.cc:686] CHECK_STREQ failed: (string("a")+"b").c_str() == "abc" (ab vs. abc)
*** Check failure stack trace: ***
F20230424 13:28:15.469203 2128115 logging_unittest.cc:680] CHECK_STREQ failed: nullptr == "this" ( vs. this)
F20230424 13:28:15.469218 2128115 logging_unittest.cc:681] CHECK_STREQ failed: "this" == "siht" (this vs. siht)
F20230424 13:28:15.469231 2128115 logging_unittest.cc:682] CHECK_STRCASEEQ failed: nullptr == "siht" ( vs. siht)
F20230424 13:28:15.469252 2128115 logging_unittest.cc:683] CHECK_STRCASEEQ failed: "this" == "siht" (this vs. siht)
F20230424 13:28:15.469266 2128115 logging_unittest.cc:684] CHECK_STRNE failed: nullptr != nullptr ( vs. )
F20230424 13:28:15.469280 2128115 logging_unittest.cc:685] CHECK_STRNE failed: "this" != "this" (this vs. this)
F20230424 13:28:15.469293 2128115 logging_unittest.cc:686] CHECK_STREQ failed: (string("a")+"b").c_str() == "abc" (ab vs. abc)
F20230424 13:28:15.469306 2128115 logging_unittest.cc:701] Check failed: 'static_cast<void*>(nullptr)' Must be non NULL
```

这里是与ASSERT_DEATH的使用有一定关系的，首先可以了解一下ASSERT_DEATH的设计:
<code>ASSERT_DEATH</code>是通过在子进程中运行测试代码，并检查子进程是否由于致命错误而终止实现的
那么我们这里以前两条语句为例:
```
CHECK_STREQ() 实际是经过了glog中封装出来的一个宏
最后会由LOG(FATAL) 输出所有信息
ASSERT_DEATH(CHECK_STREQ(nullptr, "this"), "");
ASSERT_DEATH(CHECK_STREQ("this", "siht"), "");
```
CHECK_STREQ是一个用于判定字符串是否相等的工具，第一条语句都是无法通过测试的，那么这个测试就会在此终止。
第一条打印出日志后，子进程就会正常终止了，记住此时的缓存留存了第一个日志打印。
那么第二条还是会被执行是因为:
ASSERT_DEATH 宏中实现了重置测试环境的操作。在 gtest.h 中，ASSERT_DEATH 宏使用了 GTEST_SUPPRESS_UNREACHABLE_CODE_WARNING_BELOW_ 宏和 GTEST_EXECUTE_UNTIL_FATAL 宏来实现这个操作。这个宏的作用是在 ASSERT_DEATH 的断言失败后，执行 GTEST_EXECUTE_UNTIL_FATAL 中的代码来重置测试环境，使得下一个断言可以重新执行。因此，即使前一个 ASSERT_DEATH 断言失败了，后续的 ASSERT_DEATH 断言也可以被执行。
那还有一个问题，就是为什么第一个缓存的日志，应该在打印第二个日志时就被输出完毕了，可是执行第三条语句时，我仍可以看见前面的日志输出？
这是因为在第三个ASSERT_DEATH语句执行之前，第一个ASSERT_DEATH语句的缓存还未被清空。在Google Test中，缓存的清空是在当前测试函数执行完毕后才进行的，而不是在每个ASSERT_DEATH语句执行之后。因此，如果一个ASSERT_DEATH语句失败，那么在该测试函数执行完毕之前，之前所有的缓存仍然会保留。这也是为什么后续的ASSERT_DEATH语句会继续打印之前的缓存日志。

所以一般情况，我们是不推荐大家去使用ASSERT_DEATH去连续的记录日志的信息，因为同环境下的缓存对于日志的影响也很大。


这里的一共有十二个测试用例，但还有三个没有通过，就是最后一个TEST的
```
TEST(UserDefinedClass, logging) {
  UserDefinedClass u;
  vector<string> buf;
  LOG_STRING(INFO, &buf) << u;
  
  CHECK_EQ(1UL, buf.size());
  CHECK(buf[0].find("OK") != string::npos);

  // We must be able to compile this.
  CHECK_EQ(u, u);
}
```
为什么没有通过，可以细究一下 CHECK_EQ的实现
```
#define CHECK_EQ(val1, val2) CHECK_OP(_EQ, ==, val1, val2)

#if defined(STATIC_ANALYSIS)
// Only for static analysis tool to know that it is equivalent to assert
#define CHECK_OP_LOG(name, op, val1, val2, log) CHECK((val1) op (val2))
#elif DCHECK_IS_ON()
// In debug mode, avoid constructing CheckOpStrings if possible,
// to reduce the overhead of CHECK statments by 2x.
// Real DCHECK-heavy tests have seen 1.5x speedups.

// The meaning of "string" might be different between now and
// when this macro gets invoked (e.g., if someone is experimenting
// with other string implementations that get defined after this
// file is included).  Save the current meaning now and use it
// in the macro.
#if GOOGLE_STRIP_LOG <= 3
#define CHECK_OP(name, op, val1, val2) \
  CHECK_OP_LOG(name, op, val1, val2, @ac_google_namespace@::LogMessageFatal)
#else
#define CHECK_OP(name, op, val1, val2) \
  CHECK_OP_LOG(name, op, val1, val2, @ac_google_namespace@::NullStreamFatal)
#endif // STRIP_LOG <= 3

#define CHECK_OP_LOG(name, op, val1, val2, log)                         \
  while (@ac_google_namespace@::CheckOpString _result =                 \
         @ac_google_namespace@::Check##name##Impl(                      \
             @ac_google_namespace@::GetReferenceableValue(val1),        \
             @ac_google_namespace@::GetReferenceableValue(val2),        \
             #val1 " " #op " " #val2))                                  \
    log(__FILE__, __LINE__, _result).stream()
#endif  // STATIC_ANALYSIS, DCHECK_IS_ON()


// Helper functions for string comparisons.
// To avoid bloat, the definitions are in logging.cc.
#define DECLARE_CHECK_STROP_IMPL(func, expected) \
  GLOG_EXPORT std::string* Check##func##expected##Impl( \
      const char* s1, const char* s2, const char* names);
DECLARE_CHECK_STROP_IMPL(strcmp, true)
DECLARE_CHECK_STROP_IMPL(strcmp, false)
DECLARE_CHECK_STROP_IMPL(strcasecmp, true)
DECLARE_CHECK_STROP_IMPL(strcasecmp, false)
#undef DECLARE_CHECK_STROP_IMPL



// Helper functions for string comparisons.
#define DEFINE_CHECK_STROP_IMPL(name, func, expected)                         \
  string* Check##func##expected##Impl(const char* s1, const char* s2,         \
                                      const char* names) {                    \
    bool equal = s1 == s2 || (s1 && s2 && !func(s1, s2));                     \
    if (equal == expected)                                                    \
      return nullptr;                                                         \
    else {                                                                    \
      ostringstream ss;                                                       \
      if (!s1) s1 = "";                                                       \
      if (!s2) s2 = "";                                                       \
      ss << #name " failed: " << names << " (" << s1 << " vs. " << s2 << ")"; \
      return new string(ss.str());                                            \
    }                                                                         \
  }
DEFINE_CHECK_STROP_IMPL(CHECK_STREQ, strcmp, true)
DEFINE_CHECK_STROP_IMPL(CHECK_STRNE, strcmp, false)
DEFINE_CHECK_STROP_IMPL(CHECK_STRCASEEQ, strcasecmp, true)
DEFINE_CHECK_STROP_IMPL(CHECK_STRCASENE, strcasecmp, false)
#undef DEFINE_CHECK_STROP_IMPL
```

单元测试顺序
======== Passed 13 test suites =============
1. DeathNoAllocNewHook logging
2. DeathRawCHECK
3. DeathSTREQ
4. CheckNOTNULL
5. DeathCheckNN
6. SafeFNMatch
7. Strerror
8. DVLog
9. LogAtLevel
10. TestExitOnDFatal
11. LogBacktraceAt
12. UserDefinedClass
13. LogMsgTime

======== Passed 15 test suites =============

测试函数
============================================
  TestLogging(true);
  TestRawLogging();
  TestLoggingLevels();
  TestVLogModule();
  TestLogString();
  TestLogSink();
  TestLogToString();
  TestLogSinkWaitTillSent();
  TestCHECK();
  TestDCHECK();
  TestSTREQ();
  TestBasename();
  TestBasenameAppendWhenNoTimestamp();
  TestTwoProcessesWrite();
  TestSymlink();
  TestExtension();
  TestWrapper();
  TestErrno();
  TestTruncate();
  TestCustomLoggerDeletionOnShutdown();
  TestLogPeriodically();


============================================


那么GLOG下的GoogleTest中主要使用了什么进行测试，首先上午先将googlemock添加到项目中
这个已经添加到项目中了，可调试信息也更多了

为了保证不污染 "/tmp"目录，我将日志的生成路径修改到 ./test目录下了
根据代码，很明显glog中的并没有完全使用google test进行代码的单元测试
更多的测试则是通过大部分的函数去进行的测试，那为什么呢？

首先先将现在已经已有的测试表单进行分析.
DeathNoAllocNewHook 测试的目的:
1. 测试了Fatal 是否会崩溃
2. Fatal 导致的崩溃是因为会在最后调用一个abort

DeathRawCHECK 测试目的:
1. RAW_CHECK的具体的流程如下:
  RAW_DCHECK -> RAW_CHECK -> RAW_LOG(FATAL) -> RAW_LOG_FATAL -> RawLog__ -> DoRawLog ->
VADoRawLog  -> 打印日志 -> LogMessage::Fail() -> abort -> failed -> ASSERT_DEATH -> 捕抓异常 -> 结束
如果我将其修改成
```
ASSERT_DEBUG_DEATH(RAW_DCHECK(1 == 2, "failure 2"),
             "RAW: ppoj 9999999999999999999999999999");
```
那么这时就会报错，同时打印出 "RAW: ppoj
9999999999999999999999999999",所有的测试也会在此中断
因为他在扩展时会对
condition进行判断，如是失败，则不进行之后的操作，因而也会在此被中断，此时也会打印出宏的所有展开形式.
因此如果想要知道其宏的展开形式的话，可以使用这个方法。

为什么使用
ASSERT_DEBUG_DEATH，因为许多的问题不会在Release版本下抛出，但是会在Debug中抛出，因此google
test提供了针对Debug版本的ASSERT_*。

DeathSTEQ 测试目的:
如果执行失败，会断开执行，这里使用的是
ASSERT_DEATH不会得到失败时的宏展开，因此使用ASSERT_DEBUG_DEATH，即可得到相应的宏展开形式:
```
while (google::CheckOpString _result = 
       google::CheckstrcmptrueImpl(("this"), ("this"), "\"this\"" " " "==" " " "\"this\"")) 
       google::LogMessageFatal
       ( "/root/mine/Project/glog/src/logging_unittest.cc", 697).stream() << *_result.str_
```
但是这些日志都是在测试Fatal等级的日志

CheckNotNull 测试目的:
1. 这里代码流程走的是 reuturn Forward<T>(t)，所以日志上没有什么返回值
2. 这里也需要注意的是，int
   作为基础类型，一但被定义那么它就不在是空值，这里的test也是因此而通过了判空测试

DeathCheckNN 测试目的:
1. 这里对CHECK_NOTNULL 进行了一个失败的测试，这样也是通过了测试

SafeFNMatch 测试目的:
1. 这里基于fnmatch()重写了一个状态机，对字符进行比较

Strerror 测试目的:
1.
这里测试了errorcode的信息，不过考虑到POSIX与GUN在设计的不同，设置errorcode信息时，采用了不同的表示方式

DVLOG 测试目的:
EXPECT_CALL 是Google Mock
框架下的一个函数，传入一个mock对象，并根据提供一个需要测试的函数
EXPECT_CALL(log, Log(GLOG_INFO, __FILE__), "debug log");
DVLOG(1) << "debug log"
在这里 google mock框架会自动验证 `EXPECT_CALL`中设置的预期调用
它会调用log.Log函数 是否会如预期被调用一次，并且参数是否一致


 LogAtLevel 测试目的:
是一个Mock的测试

TestExitOnDFatal
mock函数

LogBacktraceAt

UserDefinedClass

LogMsgTime

Mock流程


# 难点问题
1. 如何清除ASSERT_DEATH(LOG(FATAL))
   中会存在于ASSERT_DEATH中存在的缓存残留问题，我这里应该如何让他清除残留的缓存呢？

