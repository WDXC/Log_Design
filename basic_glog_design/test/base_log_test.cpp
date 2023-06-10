#include "base_log.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <iostream>

using testing::InitGoogleTest;
using testing::_;


int main() {
    std::cout << "helo " << std::endl;
    setbuf(stderr, nullptr);
    InitGoogleTest();
    EXPECT_EQ(RUN_ALL_TESTS(), 0);
}

static void NoAllocNewHook() {
  LOG(FATAL) << "unexpected new";
}

struct NewHook {
  NewHook() {
    g_new_hook = &NoAllocNewHook;
  }
  ~NewHook() { g_new_hook = nullptr; }
};

TEST(DeathNoAllocNewHook, logging) {
    // tests that NewHook used below works
    NewHook new_hook;
    ASSERT_DEATH({

            })
}
