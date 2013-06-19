CROSS_PREFIX = mipsel-linux-uclibc-
GCC = $(CROSS_PREFIX)gcc
STRIP = $(CROSS_PREFIX)strip

CFLAGS = -std=gnu99 -Wall -Werror

TARGET = xclient
OBJS = xclient.o adapter.o eap.o encrypt.o

all: $(TARGET)

%.o: %.c
	$(GCC) $(CFLAGS) -o $@ -c $< 

$(TARGET): $(OBJS)
	$(GCC) -static -o $@ $(CFLAGS) $^
	$(STRIP) $@

.PHONY: clean

clean:
	rm -rf *.o $(TARGET)
