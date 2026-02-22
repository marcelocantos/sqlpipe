MAKEFLAGS += -j$(shell sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)

# ── Toolchain ────────────────────────────────────────────────────────
CC       := cc
CXX      := c++
AR       := ar
CFLAGS   := -w -DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_PREUPDATE_HOOK
CXXFLAGS := -std=c++20 -Wall -Wextra -Wpedantic \
            -DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_PREUPDATE_HOOK

VENDOR := vendor
INCFLAGS := -I. -I$(VENDOR)/include -I$(VENDOR)/github.com/gabime/spdlog/include

BUILD := build

# ── Sources ──────────────────────────────────────────────────────────
SQLITE_SRC   := $(VENDOR)/src/sqlite3.c
LIB_CXX_SRCS := sqlpipe.cpp

TEST_SRCS := tests/doctest_main.cpp tests/test_protocol.cpp \
             tests/test_master.cpp tests/test_replica.cpp \
             tests/test_integration.cpp tests/test_resync.cpp

EXAMPLE_SRCS := examples/loopback.cpp

# ── Objects ──────────────────────────────────────────────────────────
SQLITE_OBJ   := $(BUILD)/sqlite3.o
LIB_CXX_OBJS := $(BUILD)/sqlpipe.o
TEST_OBJS     := $(patsubst %.cpp,$(BUILD)/%.o,$(TEST_SRCS))
EXAMPLE_OBJS  := $(patsubst %.cpp,$(BUILD)/%.o,$(EXAMPLE_SRCS))

LIB      := $(BUILD)/libsqlpipe.a
TESTS    := $(BUILD)/sqlpipe_tests
LOOPBACK := $(BUILD)/loopback

# ── Phony targets ────────────────────────────────────────────────────
.PHONY: all test example clean

all: $(LIB)

test: $(TESTS)
	$(TESTS)

example: $(LOOPBACK)
	$(LOOPBACK)

clean:
	rm -rf $(BUILD)

# ── Build rules ──────────────────────────────────────────────────────
$(LIB): $(SQLITE_OBJ) $(LIB_CXX_OBJS)
	$(AR) rcs $@ $^

$(TESTS): $(TEST_OBJS) $(LIB)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_OBJS) $(LIB)

$(LOOPBACK): $(EXAMPLE_OBJS) $(LIB)
	$(CXX) $(CXXFLAGS) -o $@ $(EXAMPLE_OBJS) $(LIB)

# sqlite3.c compiled as C
$(SQLITE_OBJ): $(SQLITE_SRC) | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

# Library source
$(BUILD)/sqlpipe.o: sqlpipe.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(INCFLAGS) -c -o $@ $<

# Test sources
$(BUILD)/tests/%.o: tests/%.cpp | $(BUILD)/tests
	$(CXX) $(CXXFLAGS) $(INCFLAGS) -c -o $@ $<

# Example sources
$(BUILD)/examples/%.o: examples/%.cpp | $(BUILD)/examples
	$(CXX) $(CXXFLAGS) $(INCFLAGS) -c -o $@ $<

# ── Output directories ───────────────────────────────────────────────
$(BUILD) $(BUILD)/tests $(BUILD)/examples:
	mkdir -p $@
