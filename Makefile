CC=g++
CFLAGS=-c -Wall
LDFLAGS=
SOURCES=main.cpp nfv5.cpp
OBJECTS=$(SOURCES:.cpp=.o)
LIBS=-lpcap -lrt
EXECUTABLE=nf5exporter

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ ${LIBS}

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(OBJECTS) $(EXECUTABLE)
    
