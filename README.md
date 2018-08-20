# TCPSniff
TCPSniff is a command-line tool to sniff network packets.

# Build
### Linux
If you are on a Debian/Debian-based system run this to install dependencies:
```sudo apt-get install mingw-w64```
And then run ```make``` which will compile a x86 and an x86_64 executable.

### Windows
If you are on a Windows system you must install MinGW and then run the recepies from the Makefile.

# Usage
Run ```tcpsniff.exe``` without any arguments, you will get a short menu with all options.

# Example
Here is an example on how to sniff passwords:

```C:\tcpsniff>tcpsniff.exe -i 1 -D -p tcp | findstr /I "post"```

This will search for all post requests, if someone is sending credentials to an unsecure website you will sniff that post request and get their password.

# License
[MIT](LICENSE)
