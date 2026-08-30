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
LDLIBS        := -lacl

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

# Tests : toujours compilés avec ASan/UBSan, indépendamment du profil principal
check: $(TESTBINS)
	@fail=0; \
	for t in $^; do ./$$t || fail=$$((fail+1)); done; \
	[ $$fail -eq 0 ]

$(BUILDDIR)/test_%: $(TESTDIR)/test_%.c $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

# test_access links all modules it orchestrates
$(BUILDDIR)/test_access: $(TESTDIR)/test_access.c \
    $(SRCDIR)/access.c $(SRCDIR)/permissions.c \
    $(SRCDIR)/path.c   $(SRCDIR)/user.c | $(BUILDDIR)
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS)

clean:
	$(RM) -r $(BUILDDIR) $(TARGET)
