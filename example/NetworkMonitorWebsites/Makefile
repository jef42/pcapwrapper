COMPILER = g++
COPTIONS = -std=c++14 -Wall -Wextra -O3

LIB_PATH = 	-L/usr/lib/pcapwrapper

LIBS =	-lpcapwrapper \
 	-lpcap \
	-pthread

GCC = $(COMPILER) $(COPTIONS)

all: output

HEADER =	httpsessioncontroller.h \
			httpworker.h

CORE =	main.o \
	httpsessioncontroller.o \
	httpworker.o

%.o: %.cpp $(HEADER)
	$(GCC) -c -o $@ $<

output:		$(CORE)
		$(GCC) $(CORE) -o ../builds/NetworkMonitorWebsites $(LIB_PATH) $(LIBS)

clean:	
	rm *.o
	rm ../builds/NetworkMonitorWebsites
