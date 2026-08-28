CC      ?= cc
TARGET  := y-not

SRCDIR   := src
INCDIR   := include
BUILDDIR := build

SRCS := $(wildcard $(SRCDIR)/*.c)
OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)

CFLAGS_BASE    := -std=c11 -Wall -Wextra -Wpedantic -I$(INCDIR) \
                  -fstack-protector-strong -MMD -MP
CFLAGS_RELEASE := $(CFLAGS_BASE) -O2 -DNDEBUG
CFLAGS_DEBUG   := $(CFLAGS_BASE) -O0 -g3 -fsanitize=address,undefined -DDEBUG

LDFLAGS       :=
LDFLAGS_DEBUG := -fsanitize=address,undefined

# Honour CFLAGS from environment, default to release profile
CFLAGS ?= $(CFLAGS_RELEASE)

PREFIX ?= /usr/local
BINDIR := $(DESTDIR)$(PREFIX)/bin

.PHONY: all debug clean install

all: $(TARGET)

debug: CFLAGS  := $(CFLAGS_DEBUG)
debug: LDFLAGS := $(LDFLAGS_DEBUG)
debug: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILDDIR):
	mkdir -p $@

# Auto-generated header dependency tracking
-include $(DEPS)

install: all
	install -Dm755 $(TARGET) $(BINDIR)/$(TARGET)

clean:
	$(RM) -r $(BUILDDIR) $(TARGET)
