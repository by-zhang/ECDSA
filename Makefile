CC = g++
OPENSSLFLAG = -lcrypto
OBJECTS = main.o ecdsa.o 
EXEC = main

install: $(OBJECTS)
	$(CC) -o $(EXEC) $(OBJECTS) $(OPENSSLFLAG)
main.o: main.cc
	$(CC) -c main.cc
ecdsa.o: ecdsa.cc ecdsa.h
	$(CC) -c ecdsa.cc
clean: 
	rm -rf $(OBJECTS)
