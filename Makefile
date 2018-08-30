FLAGS=-pipe -O3 -static-libgcc -lwsock32

all: tcpsniff.exe tcpsniff64.exe

tcpsniff.exe:
	i686-w64-mingw32-gcc $(FLAGS) *.c -o tcpsniff.exe

tcpsniff64.exe:
	x86_64-w64-mingw32-gcc $(FLAGS) *.c -o tcpsniff64.exe

clean:
	rm -f tcpsniff.exe tcpsniff64.exe
