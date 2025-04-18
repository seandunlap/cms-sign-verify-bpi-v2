CC = gcc
CFLAGS = -I/opt/homebrew/Cellar/openssl@3/3.4.1/include
LDFLAGS = -L/opt/homebrew/Cellar/openssl@3/3.4.1/lib
LIBS = -lssl -lcrypto
TARGET = authReqSignature
SOURCE = authReqSignature.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET) $(LDFLAGS) $(LIBS)

clean:
	rm -f $(TARGET)
