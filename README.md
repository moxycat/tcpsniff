# TCPSniff
TCPSniff is a command-line tool to sniff network packets.

# Build
Open the files in a Visual Studio project and build.

# Usage
Run ```tcpsniff.exe``` without any arguments, you will get a short menu with all options.

# Example
Here is an example on how to sniff passwords:

```C:\tcpsniff>tcpsniff.exe -i 1 -D -p tcp | findstr /I "post"```

This will search for all post requests, if someone is sending credentials to an unsecure website you will sniff that post request and get their password.

# License
[MIT](LICENSE)
