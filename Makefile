CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -std=c11 -O2 -g
LDFLAGS = -lpthread -latomic
SRCDIR  = src
BUILD   = build

SRCS    = $(SRCDIR)/slab.c $(SRCDIR)/vmem.c $(SRCDIR)/main.c
OBJS    = $(patsubst $(SRCDIR)/%.c,$(BUILD)/%.o,$(SRCS))
TARGET  = $(BUILD)/slab_test

VMEM_TARGET = $(BUILD)/vmem_test

.PHONY: all clean run test

all: $(TARGET) $(VMEM_TARGET)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: $(SRCDIR)/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(VMEM_TARGET): $(BUILD)/vmem.o $(BUILD)/vmem_test.o
	$(CC) $(CFLAGS) $^ -o $@ -lpthread

run: $(TARGET)
	./$(TARGET)

test: $(TARGET) $(VMEM_TARGET)
	./$(TARGET)
	./$(VMEM_TARGET)

clean:
	rm -rf $(BUILD)
