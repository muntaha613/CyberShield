CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -pthread
all: engine/cybershield
engine/cybershield: engine/main.cpp
	$(CXX) $(CXXFLAGS) $< -o $@
run: all
	python3 gui/app.py
clean:
	rm -f engine/cybershield
.PHONY: all run clean
