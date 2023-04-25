# 单元测试分析(logging_unittest)

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


这里的一共有十一个测试用例，日志信息明确的告知我们仅通过了九个测试用例，那么这里不通过的用例则是:
```
1. ASSERT_DEBUG_DEATH(RAW_DCHECK(1 == 2, "failure 2"), "RAW: Check 1 == 2 failed: failure 2");
2. ASSERT_DEATH(CHECK_STREQ("this", "siht"), "");
```

首先第一个，RAW_DCHECK判断时是false的，但是等到的结果与期望字符串"ear
