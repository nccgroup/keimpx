# On Windows
#CC=mingw32-gcc
# On Ubuntu
CC=i586-mingw32msvc-gcc
# On some other Linux
#CC=i486-mingw32-gcc
CFLAGS=-Wall -pedantic -O3

srv_bindshell:
	-$(CC) $(CFLAGS) srv_bindshell.c -o srv_bindshell.exe -lws2_32
	-strip srv_bindshell.exe
