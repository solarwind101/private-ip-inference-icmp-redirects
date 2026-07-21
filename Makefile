CXX      = g++
CXXFLAGS = -std=c++17 -O2 -Wall
LDFLAGS  = -ltins -lpcap -lpthread

all: attack_s port_infer

attack_s: attack_s.cpp common.h
	$(CXX) $(CXXFLAGS) -o $@ attack_s.cpp $(LDFLAGS)

port_infer: port_infer.cpp
	$(CXX) $(CXXFLAGS) -o $@ port_infer.cpp $(LDFLAGS)

clean:
	rm -f attack_s port_infer
