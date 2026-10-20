CC      ?= cc
TARGET  := y-not
VERSION := 1.3.0

# Single source of truth for the packaging maintainer (control + changelog).
MAINTAINER := Elena Frison <e_gavrilova_frison@zohomail.eu>

SRCDIR   := src
INCDIR   := include
BUILDDIR := build

SRCS := $(wildcard $(SRCDIR)/*.c) $(wildcard $(SRCDIR)/*/*.c)
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
	@mkdir -p $(dir $@)
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

# Each test binary is linked explicitly against the module(s) it exercises;
# module .c files live under src/<group>/ now, so no single generic pattern
# rule can match every test_<name>.c -> src/<name>.c pair like it used to.
$(BUILDDIR)/test_user: $(TESTDIR)/test_user.c \
    $(SRCDIR)/resolve/user.c | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

# path.c queries SELinux for each component's context
$(BUILDDIR)/test_path: $(TESTDIR)/test_path.c \
    $(SRCDIR)/resolve/path.c $(SRCDIR)/context/selinux_info.c | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

# test_permissions exercises the ACL fallback and DAC-capability bypass too
$(BUILDDIR)/test_permissions: $(TESTDIR)/test_permissions.c \
    $(SRCDIR)/permissions/permissions.c $(SRCDIR)/permissions/acl_eval.c \
    $(SRCDIR)/permissions/mode_bits.c $(SRCDIR)/permissions/capabilities.c | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

# test_capabilities exercises the capability.conf parser directly
$(BUILDDIR)/test_capabilities: $(TESTDIR)/test_capabilities.c \
    $(SRCDIR)/permissions/capabilities.c $(SRCDIR)/permissions/mode_bits.c | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

$(BUILDDIR)/test_selinux_info: $(TESTDIR)/test_selinux_info.c \
    $(SRCDIR)/context/selinux_info.c | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

$(BUILDDIR)/test_apparmor_info: $(TESTDIR)/test_apparmor_info.c \
    $(SRCDIR)/context/apparmor_info.c | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

# Unit-test check_access orchestration with controlled path/permission providers.
$(BUILDDIR)/test_access_policy: $(TESTDIR)/test_access_policy.c \
    $(SRCDIR)/access.c | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

# test_access links all modules it orchestrates
$(BUILDDIR)/test_access: $(TESTDIR)/test_access.c \
    $(SRCDIR)/access.c \
    $(SRCDIR)/permissions/permissions.c $(SRCDIR)/permissions/acl_eval.c \
    $(SRCDIR)/permissions/mode_bits.c $(SRCDIR)/permissions/capabilities.c \
    $(SRCDIR)/context/selinux_info.c \
    $(SRCDIR)/resolve/path.c $(SRCDIR)/resolve/user.c | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

$(BUILDDIR)/test_explanation: $(TESTDIR)/test_explanation.c \
    $(SRCDIR)/render/explanation.c | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

# Status providers are mocked in test_output for deterministic active/inactive cases.
$(BUILDDIR)/test_output: $(TESTDIR)/test_output.c \
    $(SRCDIR)/render/output.c $(SRCDIR)/render/explanation.c | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

$(BUILDDIR)/test_json_output: $(TESTDIR)/test_json_output.c \
    $(SRCDIR)/render/json_output.c $(SRCDIR)/render/explanation.c | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

$(BUILDDIR)/test_mode_bits: $(TESTDIR)/test_mode_bits.c \
    $(SRCDIR)/permissions/mode_bits.c | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

# Isolate the capability-aware DAC branches from host pam_cap configuration.
$(BUILDDIR)/test_permission_capabilities: $(TESTDIR)/test_permission_capabilities.c \
    $(SRCDIR)/permissions/permissions.c $(SRCDIR)/permissions/acl_eval.c \
    $(SRCDIR)/permissions/mode_bits.c | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

# Mock NSS group responses so getgrouplist() growth is tested deterministically.
$(BUILDDIR)/test_user_lookup_mock: $(TESTDIR)/test_user_lookup_mock.c \
    $(SRCDIR)/resolve/user.c | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

clean:
	$(RM) -r $(BUILDDIR) $(TARGET)

# Code coverage: build in an isolated directory so gcov objects cannot be
# accidentally reused by the normal build or leave the root binary instrumented.
# Test failures must fail this target rather than yield a misleading report.
CFLAGS_COVERAGE := $(CFLAGS_BASE) -O0 -g --coverage

.PHONY: coverage coverage-run
coverage:
	$(RM) -r $(BUILDDIR)/coverage
	$(MAKE) BUILDDIR=$(BUILDDIR)/coverage TARGET=$(BUILDDIR)/coverage/y-not \
	    CFLAGS='$(CFLAGS_COVERAGE)' CFLAGS_DEBUG='$(CFLAGS_COVERAGE)' \
	    LDFLAGS=--coverage LDLIBS='$(LDLIBS) --coverage' coverage-run

coverage-run: $(TARGET) $(TESTBINS)
	@fail=0; \
	for t in $(TESTBINS); do \
	    if ! ./$$t >/dev/null 2>&1; then echo "FAILED: $$t"; fail=1; fi; \
	done; \
	if ! Y_NOT_BIN=./$(TARGET) ./$(TESTDIR)/test_cli.sh >/dev/null 2>&1; then \
	    echo "FAILED: $(TESTDIR)/test_cli.sh"; fail=1; \
	fi; \
	[ $$fail -eq 0 ]
	lcov --capture --directory $(BUILDDIR) --output-file $(BUILDDIR)/coverage.info \
	    --ignore-errors inconsistent --rc branch_coverage=1 >/dev/null
	lcov --remove $(BUILDDIR)/coverage.info '$(TESTDIR)/*' '/usr/*' --output-file $(BUILDDIR)/coverage.info \
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
# DEBIAN/control from the template (version, architecture and auto-generated
# runtime dependencies substituted), then let dpkg-deb do the rest. Built and
# published on every version tag (see .github/workflows/release.yml).
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
	# Policy-valid Debian changelog. The rich upstream notes ship separately
	# as changelog.gz (free-form, which lintian allows once a changelog.Debian
	# is present). Date honours SOURCE_DATE_EPOCH for reproducible builds.
	d=$$(date -R $${SOURCE_DATE_EPOCH:+-d @$$SOURCE_DATE_EPOCH}); \
	printf '%s (%s) unstable; urgency=medium\n\n  * Upstream release %s; see changelog.gz for details.\n\n -- %s  %s\n' \
	    '$(TARGET)' '$(VERSION)' '$(VERSION)' '$(MAINTAINER)' "$$d" \
	    | gzip -9n > $(BUILDDIR)/changelog.Debian.gz
	install -Dm644 $(BUILDDIR)/changelog.Debian.gz $(DEBROOT)/usr/share/doc/$(TARGET)/changelog.Debian.gz
	mkdir -p $(DEBROOT)/DEBIAN
	# Runtime dependencies are generated by dpkg-shlibdeps rather than written
	# by hand: it reads the binary's NEEDED libraries and emits each providing
	# package with the correct minimum version (e.g. libc6 (>= 2.34)), so the
	# package can never claim to work on a glibc too old to run it. It insists
	# on reading a debian/control, so we hand it a minimal stub and capture
	# shlibs:Depends from -O (stdout) instead of a substvars file.
	mkdir -p $(BUILDDIR)/shlibdeps/debian
	printf 'Source: %s\n\nPackage: %s\nArchitecture: %s\n' \
	    '$(TARGET)' '$(TARGET)' '$(DEBARCH)' > $(BUILDDIR)/shlibdeps/debian/control
	size=$$(du -k -s $(DEBROOT) | cut -f1); \
	deps=$$(cd $(BUILDDIR)/shlibdeps && dpkg-shlibdeps -O "$(abspath $(DEBROOT)/usr/bin/$(TARGET))" | sed -n 's/^shlibs:Depends=//p'); \
	[ -n "$$deps" ] || { echo "make deb: dpkg-shlibdeps produced no dependencies" >&2; exit 1; }; \
	sed -e 's/@VERSION@/$(VERSION)/' -e 's/@ARCH@/$(DEBARCH)/' \
	    -e "s/@SIZE@/$$size/" -e 's|@MAINTAINER@|$(MAINTAINER)|' \
	    -e "s|@DEPENDS@|$$deps|" \
	    packaging/debian/control.in > $(DEBROOT)/DEBIAN/control
	dpkg-deb --build --root-owner-group $(DEBROOT) $(DEBFILE)
	@echo "Built $(DEBFILE)"
