INSTALL_INCLUDE_PATH = "/usr/include/pcapwrapper"
INSTALL_LIB_PATH = "/usr/lib/pcapwrapper"

NETWORK_PACKAGES_INCLUDE_PATH = "$(INSTALL_INCLUDE_PATH)/network/packages"
NETWORK_SNIFFS_INCLUDE_PATH = "$(INSTALL_INCLUDE_PATH)/network/sniff"
NETWORK_BUILDERS_INCLUDE_PATH = "$(INSTALL_INCLUDE_PATH)/network/builders"
NETWORK_SESSIONS_INCLUDE_PATH = "$(INSTALL_INCLUDE_PATH)/network/sessions"
NETWORK_ADDRESSES_INCLUDE_PATH = "$(INSTALL_INCLUDE_PATH)/network/addresses"
HELPER_INCLUDE_PATH = "$(INSTALL_INCLUDE_PATH)/helpers"
HELPER_LISTENERS_INCLUDE_PATH = "$(INSTALL_INCLUDE_PATH)/helpers/listeners"
LISTENERS_INCLUDE_PATH = "$(INSTALL_INCLUDE_PATH)/listeners"
MAIN_INCLUDE_PATH = "$(INSTALL_INCLUDE_PATH)"
INTERFACES_INCLUDE_PATH = "$(INSTALL_INCLUDE_PATH)/interfaces"
PROCESSORS_INCLUDE_PATH = "$(INSTALL_INCLUDE_PATH)/processors"
PROCESSORS_QUEUE_INCLUDE_PATH = "$(INSTALL_INCLUDE_PATH)/processors/queue"
LIB_PATH = "$(INSTALL_LIB_PATH)"

COMPILER = g++
COPTIONS = -std=c++1z -Wall -Wextra -Werror -O3

GCC = $(COMPILER) $(COPTIONS)

HEADER_NETWORK_PACKAGES = src/PCAPLib/network/packages/udppackage.h \
			src/PCAPLib/network/packages/tcppackage.h \
			src/PCAPLib/network/packages/basepackage.h \
			src/PCAPLib/network/packages/arppackage.h \
			src/PCAPLib/network/packages/icmppackage.h \
			src/PCAPLib/network/packages/ippackage.h \
			src/PCAPLib/network/packages/ethernetpackage.h \
			src/PCAPLib/network/packages/packageutils.h

HEADER_NETWORK_BUILDERS = src/PCAPLib/network/builders/builder.h \
						  src/PCAPLib/network/builders/keys.h

HEADER_NETWORK_SNIFFS = 	src/PCAPLib/network/sniff/snifficmp.h \
			src/PCAPLib/network/sniff/snifftcp.h \
			src/PCAPLib/network/sniff/sniffudp.h \
			src/PCAPLib/network/sniff/sniffethernet.h \
			src/PCAPLib/network/sniff/sniffip.h \
			src/PCAPLib/network/sniff/sniffarp.h

HEADER_NETWORK_ADDRESSES = src/PCAPLib/network/addresses/ipaddress.h \
						   src/PCAPLib/network/addresses/macaddress.h

HEADER_NETWORK_SESSIONS = src/PCAPLib/network/sessions/sessioncontroller.h \
			src/PCAPLib/network/sessions/session.h

HEADER_HELPERS =	src/PCAPLib/helpers/helper.h \
			src/PCAPLib/helpers/constants.h

HEADER_HELPERS_LISTENERS =	src/PCAPLib/helpers/listeners/maclistener.h 

HEADER_LISTENERS = 	src/PCAPLib/listeners/packagelistener.h 

HEADER_MAIN = 	src/PCAPLib/controller.hpp \
				src/PCAPLib/performancemeasurement.h
		
HEADER_PROCESSORS = src/PCAPLib/processors/processorpolicy.h \
		src/PCAPLib/processors/processorempty.h \
		src/PCAPLib/processors/processor.h \
		src/PCAPLib/processors/processorsave.h \
		src/PCAPLib/processors/processorqueue.h

HEADER_PROCESSORS_QUEUE = src/PCAPLib/processors/queue/rawpackage.h \
		src/PCAPLib/processors/queue/queue.hpp \

HEADER_INTERFACES = src/PCAPLib/interfaces/interface.h \
		src/PCAPLib/interfaces/interfacepolicy.h \
		src/PCAPLib/interfaces/interfacethreadsafe.h \
		src/PCAPLib/interfaces/interfacefile.h
	
HEADER = $(HEADER_NETWORK_PACKAGES) $(HEADER_NETWORK_SNIFFS) $(HEADER_NETWORK_BUILDERS) $(HEADER_NETWORK_SESSIONS) \
		 $(HEADER_HELPERS) $(HEADER_LISTENERS) $(HEADER_MAIN) $(HEADER_HELPERS_LISTENERS) $(HEADER_PROCESSORS) $(HEADER_INTERFACES) 

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
all: install

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#Network

NETWORK_PACKAGES = src/PCAPLib/network/packages/basepackage.o \
		src/PCAPLib/network/packages/udppackage.o \
		src/PCAPLib/network/packages/tcppackage.o \
		src/PCAPLib/network/packages/arppackage.o \
		src/PCAPLib/network/packages/icmppackage.o \
		src/PCAPLib/network/packages/ethernetpackage.o \
		src/PCAPLib/network/packages/ippackage.o

src/PCAPLib/network/packages/%.o: src/PCAPLib/network/packages/%.cpp $(HEADER_NETWORK_PACKAGES)
	$(GCC) -c -o $@ $<
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#Network Builders

NETWORK_BUILDERS = src/PCAPLib/network/builders/builder.o 

src/PCAPLib/network/builders/%.o: src/PCAPLib/network/builders/%.cpp $(HEADER_NETWORK_BUILDERS)
	$(GCC) -c -o $@ $<
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#Network Sessions

NETWORK_SESSIONS = src/PCAPLib/network/sessions/sessioncontroller.o \
				  src/PCAPLib/network/sessions/session.o

src/PCAPLib/network/sessions/%.o: src/PCAPLib/network/sessions/%.cpp $(HEADER_NETWORK_SESSIONS)
	$(GCC) -c -o $@ $<
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#Network Addresses

NETWORK_ADDRESSES = src/PCAPLib/network/addresses/ipaddress.o \
					src/PCAPLib/network/addresses/macaddress.o

src/PCAPLib/network/addresses/%.o: src/PCAPLib/network/addresses/%.cpp $(HEADER_NETWORK_ADDRESSES)
	$(GCC) -c -o $@ $<
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#Helpers

HELPERS =	src/PCAPLib/helpers/helper.o

HELPERS_LISTENERS = src/PCAPLib/helpers/listeners/maclistener.o 

src/PCAPLib/helpers/%.o: src/PCAPLib/helpers/%.cpp $(HEADER_HELPERS)
	$(GCC) -c -o $@ $<

src/PCAPLib/helpers/listeners/%.o: src/PCAPLib/helpers/listeners/%.cpp $(HEADER_HELPERS_LISTENERS)
	$(GCC) -c -o $@ $<

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#Processors

PROCESSORS = src/PCAPLib/processors/processor.o \
		src/PCAPLib/processors/processorempty.o \
		src/PCAPLib/processors/processorsave.o \
		src/PCAPLib/processors/processorqueue.o \
		src/PCAPLib/processors/queue/queue.o

src/PCAPLib/processors/%.o: src/PCAPLib/processors/%.cpp $(HEADER_PROCESSORS)
	$(GCC) -c -o $@ $<

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#Processors Queue

PROCESSORS_QUEUE = src/PCAPLib/processors/queue/queue.o \
				   src/PCAPLib/processors/queue/rawpackage.o

src/PCAPLib/processors/queue/%.o: src/PCAPLib/processors/queue/%.hpp $(HEADER_PROCESSORS_QUEUE)
	$(GCC) -c -o $@ $<

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#Interfaces

INTERFACES = src/PCAPLib/interfaces/interface.o \
		src/PCAPLib/interfaces/interfacethreadsafe.o \
		src/PCAPLib/interfaces/interfacefile.o

src/PCAPLib/interfaces/%.o: src/PCAPLib/interfaces/%.cpp $(HEADER_INTERFACES)
	$(GCC) -c -o $@ $<
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#Main

MAIN = src/PCAPLib/performancemeasurement.o

src/PCAPLib/%.o: src/PCAPLib/%.cpp $(HEADER_MAIN)
	$(GCC) -c -o $@ $<

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
lib:		$(NETWORK_BUILDERS) $(HELPERS) $(MAIN) $(NETWORK_PACKAGES) $(NETWORK_ADDRESSES) $(NETWORK_BUILDERS_TEMPLATE) $(NETWORK_SESSIONS) $(HELPERS_LISTENERS) $(PROCESSORS) $(INTERFACES) $(PROCESSORS_QUEUE)
		ar rs src/PCAPLib/libpcapwrapper.a $(NETWORK_PACKAGES) $(NETWORK_BUILDERS) $(NETWORK_SESSIONS) $(HELPERS) $(HELPERS_LISTENERS) $(MAIN) \
		$(PROCESSORS) $(INTERFACES) $(PROCESSORS_QUEUE) $(NETWORK_ADDRESSES)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
install:	lib
		mkdir -p $(NETWORK_PACKAGES_INCLUDE_PATH)
		mkdir -p $(NETWORK_SNIFFS_INCLUDE_PATH)
		mkdir -p $(NETWORK_BUILDERS_INCLUDE_PATH)
		mkdir -p $(NETWORK_SESSIONS_INCLUDE_PATH)
		mkdir -p $(NETWORK_ADDRESSES_INCLUDE_PATH)
		mkdir -p $(HELPER_INCLUDE_PATH)
		mkdir -p $(HELPER_LISTENERS_INCLUDE_PATH)
		mkdir -p $(LISTENERS_INCLUDE_PATH)
		mkdir -p $(MAIN_INCLUDE_PATH)
		mkdir -p $(PROCESSORS_INCLUDE_PATH)
		mkdir -p $(PROCESSORS_QUEUE_INCLUDE_PATH)
		mkdir -p $(INTERFACES_INCLUDE_PATH)
		mkdir -p $(LIB_PATH)
		cp src/PCAPLib/libpcapwrapper.a $(LIB_PATH)
		cp $(HEADER_NETWORK_PACKAGES) $(NETWORK_PACKAGES_INCLUDE_PATH)
		cp $(HEADER_NETWORK_SNIFFS) $(NETWORK_SNIFFS_INCLUDE_PATH)
		cp $(HEADER_NETWORK_BUILDERS) $(NETWORK_BUILDERS_INCLUDE_PATH)
		cp $(HEADER_NETWORK_SESSIONS) $(NETWORK_SESSIONS_INCLUDE_PATH)
		cp $(HEADER_NETWORK_ADDRESSES) $(NETWORK_ADDRESSES_INCLUDE_PATH)
		cp $(HEADER_HELPERS) $(HELPER_INCLUDE_PATH)
		cp $(HEADER_HELPERS_LISTENERS) $(HELPER_LISTENERS_INCLUDE_PATH)
		cp $(HEADER_LISTENERS) $(LISTENERS_INCLUDE_PATH)
		cp $(HEADER_MAIN) $(MAIN_INCLUDE_PATH)
		cp $(HEADER_PROCESSORS) $(PROCESSORS_INCLUDE_PATH)
		cp $(HEADER_PROCESSORS_QUEUE) $(PROCESSORS_QUEUE_INCLUDE_PATH)
		cp $(HEADER_INTERFACES) $(INTERFACES_INCLUDE_PATH)
		-@ echo ""
		-@ echo "Done"

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
clean:		
		find src/PCAPLib -name "*.o" -type f -delete
		rm src/PCAPLib/libpcapwrapper.a
		-@ echo ""
		-@ echo "cleaned up"

clean-install:
		find $(INSTALL_INCLUDE_PATH) -name "*.h" -type f -delete
		find $(INSTALL_INCLUDE_PATH) -name "*.hpp" -type f -delete
		find $(INSTALL_INCLUDE_PATH) -name "*.a" -type f -delete
