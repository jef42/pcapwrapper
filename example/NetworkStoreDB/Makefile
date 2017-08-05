COMPILER = g++
COPTIONS = -std=c++14 -Wall -Wextra -O3

LIB_PATH = 	-L/usr/lib/pcapwrapper

LIBS =	-lpcapwrapper \
 	-lpcap \
	-pthread \
	-lsqlite3

GCC = $(COMPILER) $(COPTIONS)

all: output

HEADER =	networklistener.h \
			dbconnection.h

CORE =	main.o \
	networklistener.o \
	dbconnection.o \
	insertcommand.o \
	dbcommand.o

%.o: %.cpp $(HEADER)
	$(GCC) -c -o $@ $<

output:		$(CORE)
		$(GCC) $(CORE) -o ../builds/NetworkStoreDB $(LIB_PATH) $(LIBS)

clean:	
	rm *.o
	rm ../builds/NetworkReadPCAP
