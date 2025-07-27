LDLIBS += -lpcap

all: pcap-test

pcap-test: pcap-test.o

pcap-test.o: pcap-test.c pcap-test.h

clean:
	rm -f pcap-test *.o
