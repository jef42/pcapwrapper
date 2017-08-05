COMPILER = g++
COPTIONS = -std=c++14 -Wall -Wextra -O3

LIB_PATH = 	-L/usr/lib/pcapwrapper

LIBS =	-lpcapwrapper \
 	-lpcap \
	-pthread

GCC = $(COMPILER) $(COPTIONS)

all: output

HEADER =	detectnetwork.h \
		forwardpackage.h \
		isup.h

CORE =	main.o \
	detectnetwork.o \
	forwardpackage.o \
	isup.o

%.o: %.cpp $(HEADER)
	$(GCC) -c -o $@ $<

output:		$(CORE)
		$(GCC) $(CORE) -o ../builds/NetworkMonitor $(LIB_PATH) $(LIBS)

clean:	
	rm *.o
	rm ../builds/NetworkMonitor
