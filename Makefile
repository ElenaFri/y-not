CC      ?= cc
TARGET  := y-not

SRCDIR   := src
INCDIR   := include
BUILDDIR := build

SRCS := $(wildcard $(SRCDIR)/*.c)
OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)

CFLAGS_BASE    := -std=c11 -Wall -Wextra -Wpedantic -I$(INCDIR) \
                  -D_DEFAULT_SOURCE -fstack-protector-strong -MMD -MP
CFLAGS_RELEASE := $(CFLAGS_BASE) -O2 -DNDEBUG
CFLAGS_DEBUG   := $(CFLAGS_BASE) -O0 -g3 -fsanitize=address,undefined -DDEBUG

LDFLAGS       :=
LDFLAGS_DEBUG := -fsanitize=address,undefined
LDLIBS        := -lacl -lcap -lselinux

# Honour CFLAGS from environment, default to release profile
CFLAGS ?= $(CFLAGS_RELEASE)

PREFIX ?= /usr/local
BINDIR := $(DESTDIR)$(PREFIX)/bin

TESTDIR  := tests
TESTS    := $(wildcard $(TESTDIR)/test_*.c)
TESTBINS := $(patsubst $(TESTDIR)/%.c,$(BUILDDIR)/%,$(TESTS))

.PHONY: all debug check clean install

all: $(TARGET)

debug: CFLAGS  := $(CFLAGS_DEBUG)
debug: LDFLAGS := $(LDFLAGS_DEBUG)
debug: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILDDIR):
	mkdir -p $@

# Auto-generated header dependency tracking
-include $(DEPS)

install: all
	install -Dm755 $(TARGET) $(BINDIR)/$(TARGET)

# Tests are always built with ASan/UBSan, regardless of the main profile
check: $(TARGET) $(TESTBINS)
	@fail=0; \
	for t in $(TESTBINS); do ./$$t || fail=$$((fail+1)); done; \
	./$(TESTDIR)/test_cli.sh || fail=$$((fail+1)); \
	[ $$fail -eq 0 ]

$(BUILDDIR)/test_%: $(TESTDIR)/test_%.c $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

# test_permissions exercises the ACL fallback and DAC-capability bypass too
$(BUILDDIR)/test_permissions: $(TESTDIR)/test_permissions.c \
    $(SRCDIR)/permissions.c $(SRCDIR)/acl_eval.c $(SRCDIR)/mode_bits.c \
    $(SRCDIR)/capabilities.c | $(BUILDDIR)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

# test_access links all modules it orchestrates
$(BUILDDIR)/test_access: $(TESTDIR)/test_access.c \
    $(SRCDIR)/access.c $(SRCDIR)/permissions.c $(SRCDIR)/acl_eval.c $(SRCDIR)/mode_bits.c \
    $(SRCDIR)/capabilities.c $(SRCDIR)/selinux_info.c \
    $(SRCDIR)/path.c   $(SRCDIR)/user.c | $(BUILDDIR)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

# test_capabilities exercises the capability.conf parser directly
$(BUILDDIR)/test_capabilities: $(TESTDIR)/test_capabilities.c \
    $(SRCDIR)/capabilities.c $(SRCDIR)/mode_bits.c | $(BUILDDIR)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

# path.c queries SELinux for each component's context
$(BUILDDIR)/test_path: $(TESTDIR)/test_path.c \
    $(SRCDIR)/path.c $(SRCDIR)/selinux_info.c | $(BUILDDIR)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

# output.c prints the MAC status summary
$(BUILDDIR)/test_output: $(TESTDIR)/test_output.c \
    $(SRCDIR)/output.c $(SRCDIR)/selinux_info.c $(SRCDIR)/apparmor_info.c | $(BUILDDIR)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

clean:
	$(RM) -r $(BUILDDIR) $(TARGET)

# Code coverage: rebuild every test binary with gcov instrumentation, run
# them all, then summarize with lcov. Needs gcov/lcov/genhtml.
CFLAGS_COVERAGE := $(CFLAGS_BASE) -O0 -g --coverage

.PHONY: coverage
coverage: CFLAGS_DEBUG := $(CFLAGS_COVERAGE)
coverage: LDLIBS := $(LDLIBS) --coverage
coverage: clean $(TESTBINS)
	@for t in $(TESTBINS); do ./$$t >/dev/null 2>&1 || true; done
	@./$(TESTDIR)/test_cli.sh >/dev/null 2>&1 || true
	lcov --capture --directory $(BUILDDIR) --output-file $(BUILDDIR)/coverage.info \
	    --rc branch_coverage=1 >/dev/null
	genhtml $(BUILDDIR)/coverage.info --output-directory $(BUILDDIR)/coverage-html \
	    --rc branch_coverage=1 >/dev/null
	lcov --list $(BUILDDIR)/coverage.info --rc branch_coverage=1
