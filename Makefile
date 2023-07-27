PROGS = direct-indirect reuse-distance
SRCS = $(wildcard *.cc)
OBJS = $(SRCS:.cc=.o)
MAIN_OBJS = $(addsuffix .o, $(PROGS))
COMMON_OBJS = $(filter-out $(MAIN_OBJS), $(OBJS))
$(info $(COMMON_OBJS))

DEPS = $(SRCS:.cc=.d)

CXXFLAGS= -g -O3 -std=c++20 -Wall -fno-exceptions

all: $(PROGS)

$(PROGS): %: %.o $(COMMON_OBJS)
	$(CXX) $(LDFLAGS) $(LDLIBS) $^ -o $@

%.o: %.cc
	$(CXX) -c -MMD -MP $(CXXFLAGS) $< -o $@

-include $(DEPS)

.PHONY: clean
clean:
	rm -f $(OBJS) $(DEPS) $(PROGS)

.PHONY: install
install:
	mkdir -p $(PREFIX)/bin
	install -t $(PREFIX)/bin $(PROGS)
