COMPILER = g++
COPTIONS = -std=c++14 -Wall -Wextra -O3

LIB_PATH = 	-L/usr/lib/pcapwrapper

LIBS =	-lpcapwrapper \
 	-lpcap \
	-pthread

GCC = $(COMPILER) $(COPTIONS)

all: output

HEADER =	detectnetwork.h

CORE =	main.o \
	detectnetwork.o

%.o: %.cpp $(HEADER)
	$(GCC) -c -o $@ $<

output:		$(CORE)
		$(GCC) -o ../builds/DetectNetworkICMP $(CORE) $(LIB_PATH) $(LIBS)

clean:	
	rm *.o
	rm ../builds/DetectNetworkICMP
