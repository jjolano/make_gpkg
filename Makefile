TARGET = make_gpkg
CC = gcc
CXX = g++
LD = $(CXX)
CFLAGS = -Wno-deprecated-declarations
CXXFLAGS = $(CFLAGS)
LDFLAGS = -lcrypto
OBJS = main.o crypt.o

.PHONY: test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(LD) $^ $(LDFLAGS) -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	install -m755 $< $(PS3DEV)/bin

test:
	@echo Creating test.pkg ...
	@mkdir -p test/USRDIR
	@touch test/PARAM.SFO test/ICON0.PNG test/USRDIR/EBOOT.BIN
	./$(TARGET) UP0001-TEST12345_00-0000000000000000 test test.pkg

clean:
	rm -rf $(OBJS) $(TARGET) test/ test.pkg

	