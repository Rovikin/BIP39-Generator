CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra
# Note: -O2 is intentional. -O3 risks eliding the volatile wipe of entropy
# buffers, which would leave sensitive material on the stack.
TARGET   := bip39
SRCS     := bip39.cpp sha256.cpp chacha20.cpp
OBJS     := $(SRCS:.cpp=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp sha256.h chacha20.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
