CXX = g++
CXXFLAGS = -O3 -Wall

SRC = *.cpp
EXE = gre_fou
LIB = pcap


.PHONY: all clean

all:
	$(CXX) $(CXXFLAGS) $(SRC) -o $(EXE) -l $(LIB)

clean:
	@rm -f $(EXE)