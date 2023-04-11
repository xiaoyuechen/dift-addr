TARGET = clueless-trace
SRCS = $(wildcard *.cc)
OBJS = $(SRCS:.cc=.o)
DEPS = $(SRCS:.cc=.d)

CXXFLAGS= -g -O3 -std=c++20 -Wall -fno-exceptions

$(TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -o $@

%.o: %.cc
	$(CXX) -c -MMD -MP $< $(CXXFLAGS) -o $@

-include $(DEPS)

.PHONY: clean
clean:
	rm -f $(OBJS) $(DEPS) clueless-trace
