CC = gcc
CFLAGS = -Wall -O2
LDLIBS += -lpcap

TARGET = pcap-test
OBJS = pcap-test.o

all: $(TARGET)

$(TARGET): $(OBJS)

pcap-test.o: pcap-test.c pcap-test.h

clean:
	rm -f $(TARGET) $(OBJS)
