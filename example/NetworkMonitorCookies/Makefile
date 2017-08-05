COMPILER = g++
COPTIONS = -std=c++14 -Wall -Wextra -O3

LIB_PATH = 	-L/usr/lib/pcapwrapper

LIBS =	-lpcapwrapper \
 	-lpcap \
	-pthread

GCC = $(COMPILER) $(COPTIONS)

all: output

HEADER =	cookiesessioncontroller.h \
			cookieworker.h

CORE =	main.o \
	cookiesessioncontroller.o \
	cookieworker.o

%.o: %.cpp $(HEADER)
	$(GCC) -c -o $@ $<

output:		$(CORE)
		$(GCC) $(CORE) -o ../builds/NetworkMonitorCookies $(LIB_PATH) $(LIBS)

clean:	
	rm *.o
	rm ../builds/NetworkMonitorCookies
