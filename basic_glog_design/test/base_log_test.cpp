#include "base_log.h"
#include <gtest/gtest.h>
#include <iostream>


int add(int lhs, int rhs) { return lhs + rhs; }

TEST(testab, logging) {
    EXPECT_EQ(add(1,1), 2);
}


int main() {
    std::cout << "helo " << std::endl;
    RUN_ALL_TESTS();
}

