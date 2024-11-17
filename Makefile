# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -g -Wall -Wextra -Werror

# Linker flags for pcap and ncurses libraries
LDFLAGS = -lpcap -lncurses

# Target executable name
TARGET = isa-top

# Source files defined explicitly, not using wildcard to *.cpp for safety if there are any other .cpp files in the directory
SRC = isa-top.cpp isa-helper.cpp isa-printer.cpp

# Default rule (this is what gets run when you just type 'make')
all: $(TARGET)

# Rule to create the executable by linking the object files
$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

# Clean rule to remove the executable and any object files
clean:
	rm -f $(TARGET)
