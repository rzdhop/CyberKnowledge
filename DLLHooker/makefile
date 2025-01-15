CC=g++
CFLAGS=-Wall -Wextra
BUILD_DIR=build
SRC=$(wildcard ./*.cpp)
OUT=DLLHooker.exe

all: START

START: COMPILE
	$(BUILD_DIR)/$(OUT)

COMPILE: $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(BUILD_DIR)/$(OUT)
