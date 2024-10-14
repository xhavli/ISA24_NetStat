# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -g	#-Wall -Wextra -Werror	#TODO

# Linker flags for pcap
LDFLAGS = -lpcap

# Target executable
TARGET = isa-top

# Source files
SRC = isa-top.cpp

# Default rule (this is what gets run when you just type 'make')
all: $(TARGET)

# Rule to create the executable by linking the object files
$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

# Clean rule to remove the executable and any object files
clean:
	rm -f $(TARGET)
