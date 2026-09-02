CC      ?= cc
TARGET  := y-not
VERSION := 0.5.0

SRCDIR   := src
INCDIR   := include
BUILDDIR := build

SRCS := $(wildcard $(SRCDIR)/*.c)
OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)

CFLAGS_BASE    := -std=c11 -Wall -Wextra -Wpedantic -I$(INCDIR) \
                  -D_DEFAULT_SOURCE -DY_NOT_VERSION=\"$(VERSION)\" \
                  -fstack-protector-strong -MMD -MP
CFLAGS_RELEASE := $(CFLAGS_BASE) -O2 -DNDEBUG
CFLAGS_DEBUG   := $(CFLAGS_BASE) -O0 -g3 -fsanitize=address,undefined -DDEBUG

LDFLAGS       :=
LDFLAGS_DEBUG := -fsanitize=address,undefined
LDLIBS        := -lacl -lcap -lselinux

# Honour CFLAGS from environment, default to release profile
CFLAGS ?= $(CFLAGS_RELEASE)

PREFIX ?= /usr/local
BINDIR := $(DESTDIR)$(PREFIX)/bin
MANDIR := $(DESTDIR)$(PREFIX)/share/man/man1

TESTDIR  := tests
TESTS    := $(wildcard $(TESTDIR)/test_*.c)
TESTBINS := $(patsubst $(TESTDIR)/%.c,$(BUILDDIR)/%,$(TESTS))

.PHONY: all debug check clean install uninstall

all: $(TARGET)

debug: CFLAGS  := $(CFLAGS_DEBUG)
debug: LDFLAGS := $(LDFLAGS_DEBUG)
debug: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# main.c embeds VERSION via -DY_NOT_VERSION, but that's a command-line
# macro, not a file: make's timestamp-based tracking can't see it change,
# so main.o could go stale (keep an old version string) if VERSION is
# bumped without a `make clean` first. FORCE makes the check below run on
# every invocation; it only touches (and thus re-triggers) .version's own
# mtime when the content actually changed, so main.o only rebuilds then.
.PHONY: FORCE
FORCE:

$(BUILDDIR)/main.o: $(BUILDDIR)/.version

$(BUILDDIR)/.version: FORCE | $(BUILDDIR)
	@if [ ! -f $@ ] || [ "$$(cat $@ 2>/dev/null)" != "$(VERSION)" ]; then \
	    echo "$(VERSION)" > $@; \
	fi

$(BUILDDIR):
	mkdir -p $@

# Auto-generated header dependency tracking
-include $(DEPS)

install: all
	install -Dm755 $(TARGET) $(BINDIR)/$(TARGET)
	install -Dm644 man/y-not.1 $(MANDIR)/y-not.1

uninstall:
	$(RM) $(BINDIR)/$(TARGET) $(MANDIR)/y-not.1

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
	lcov --remove $(BUILDDIR)/coverage.info '$(TESTDIR)/*' --output-file $(BUILDDIR)/coverage.info \
	    --rc branch_coverage=1 >/dev/null
	genhtml $(BUILDDIR)/coverage.info --output-directory $(BUILDDIR)/coverage-html \
	    --rc branch_coverage=1 >/dev/null
	lcov --list $(BUILDDIR)/coverage.info --rc branch_coverage=1

# Valgrind smoke test on the real optimized release binary (not the ASan
# debug build - ASan/LeakSanitizer already cover leak detection on every
# `make check` run; this is a spot-check of what actually ships).
# 99 is a dedicated exit code so a real valgrind finding is distinguishable
# from y-not's own exit code (0 = allowed, 1 = denied, both legitimate).
.PHONY: valgrind
valgrind: $(TARGET)
	@fail=0; \
	me=$$(id -un); \
	for args in \
	    "$$me r /usr/bin/ls" \
	    "$$me r /bin/sh" \
	    "$$me r /var/__y_not_no_such_path__" \
	    "$$me w /etc/passwd" \
	; do \
	    valgrind --error-exitcode=99 --leak-check=full --quiet \
	        ./$(TARGET) $$args >/dev/null 2>&1; \
	    [ $$? -eq 99 ] && fail=$$((fail+1)); \
	done; \
	[ $$fail -eq 0 ]

# Debian package: stage a normal `make install` under a temp root, generate
# DEBIAN/control from the template (version + architecture substituted),
# then let dpkg-deb do the rest. Built and published on major-version tags
# only (see .github/workflows/release.yml).
DEBARCH := $(shell dpkg --print-architecture 2>/dev/null || echo amd64)
DEBROOT := $(BUILDDIR)/deb-root
DEBFILE := $(BUILDDIR)/y-not_$(VERSION)_$(DEBARCH).deb

.PHONY: deb
deb: all
	$(RM) -r $(DEBROOT)
	$(MAKE) install DESTDIR=$(DEBROOT) PREFIX=/usr
	strip --strip-unneeded $(DEBROOT)/usr/bin/$(TARGET)
	gzip -9n $(DEBROOT)/usr/share/man/man1/y-not.1
	install -Dm644 packaging/debian/copyright $(DEBROOT)/usr/share/doc/$(TARGET)/copyright
	gzip -9n -c CHANGELOG.md > $(BUILDDIR)/changelog.gz
	install -Dm644 $(BUILDDIR)/changelog.gz $(DEBROOT)/usr/share/doc/$(TARGET)/changelog.gz
	mkdir -p $(DEBROOT)/DEBIAN
	sed -e 's/@VERSION@/$(VERSION)/' -e 's/@ARCH@/$(DEBARCH)/' \
	    packaging/debian/control.in > $(DEBROOT)/DEBIAN/control
	dpkg-deb --build --root-owner-group $(DEBROOT) $(DEBFILE)
	@echo "Built $(DEBFILE)"
