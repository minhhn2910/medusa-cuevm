CXX = g++
CXXFLAGS = -std=c++11 -fPIC -Wall -O2

all: libstategpu.so

libstategpu.so: state_gpu.o
	$(CXX) -shared -o $@ $<

state_gpu.o: state_gpu.cpp state_gpu.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f *.o *.so

.PHONY: all clean