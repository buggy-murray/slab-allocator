CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -std=c11 -O2 -g
LDFLAGS = -lpthread -latomic
SRCDIR  = src
BUILD   = build

SRCS    = $(SRCDIR)/slab.c $(SRCDIR)/vmem.c $(SRCDIR)/main.c
OBJS    = $(patsubst $(SRCDIR)/%.c,$(BUILD)/%.o,$(SRCS))
TARGET  = $(BUILD)/slab_test

VMEM_TARGET = $(BUILD)/vmem_test
TAG_TARGET  = $(BUILD)/tag_test
BENCH_TARGET = $(BUILD)/bench

.PHONY: all clean run test

all: $(TARGET) $(VMEM_TARGET) $(TAG_TARGET) $(BENCH_TARGET)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: $(SRCDIR)/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(VMEM_TARGET): $(BUILD)/vmem.o $(BUILD)/vmem_test.o
	$(CC) $(CFLAGS) $^ -o $@ -lpthread

$(TAG_TARGET): $(BUILD)/slab.o $(BUILD)/vmem.o $(BUILD)/slab_tags.o $(BUILD)/test_tags.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BENCH_TARGET): $(BUILD)/slab.o $(BUILD)/vmem.o $(BUILD)/bench.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -ldl

run: $(TARGET)
	./$(TARGET)

test: $(TARGET) $(VMEM_TARGET) $(TAG_TARGET)
	./$(TARGET)
	./$(VMEM_TARGET)
	./$(TAG_TARGET)

clean:
	rm -rf $(BUILD)
