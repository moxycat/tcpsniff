# TCPSniff
TCPSniff is a command-line tool to sniff network traffic.

# Build
Run ```make.bat``` to compile the project. You will need to have MinGW installed configured to be in your ```%PATH%``` variable.

# Usage
Run ```tcpsniff.exe``` without any arguments, you will get a short menu with all options.

# Example
Here is an example on how to sniff passwords:

```C:\tcpsniff\bin> tcpsniff.exe -i 1 -d -p tcp | findstr /I "post"```

This will search for all post requests, if someone is sending credentials to an unsecure website you will sniff that post request and get their password.

# License
[MIT License](LICENSE)
