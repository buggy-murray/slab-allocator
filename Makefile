CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -std=c11 -O2 -g
LDFLAGS = -lpthread
SRCDIR  = src
BUILD   = build

SRCS    = $(SRCDIR)/slab.c $(SRCDIR)/main.c
OBJS    = $(patsubst $(SRCDIR)/%.c,$(BUILD)/%.o,$(SRCS))
TARGET  = $(BUILD)/slab_test

.PHONY: all clean run

all: $(TARGET)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: $(SRCDIR)/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	rm -rf $(BUILD)
