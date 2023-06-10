#include "base_log.h"
#include "gtest/gtest.h"
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

