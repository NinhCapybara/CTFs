CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -fno-stack-protector -fno-pie
LDFLAGS := -no-pie -Wl,-z,relro,-z,lazy
TARGET := json_parser
SRC := json_parser.cpp

all: $(TARGET)
	strip --strip-all $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

.PHONY: all clean
