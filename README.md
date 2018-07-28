# TCPSniff
TCPSniff is a command-line tool to sniff network traffic.

# Build
Run ```make.bat``` to compile the project. You will need to have MinGW installed configured to be in your ```%PATH%``` variable.

# Usage
If you run ```tcpsniff.exe``` without any arguments a short help menu will be displayed. Each short option has a corresponding long option. Here is a list explaining each one:
```
	-c, --count=<count>        Captures <count> number of packets and exits.
	-d, --dump                 Dumps packet data in ASCII readable format.
	-D, --dont-verify          Disables packet checksum verification for TCP and UDP packets.
	-i, --interface=<id>       Binds to interface with id <id> and sniffs. You can get the id using the '-l' option.
	-l, --list                 Lists all interfaces that can be used to sniff on.
	-p, --protocol=<protocol>  Displays only <protocol> packets. Can be TCP, UDP or ICMP.
	-s, --sequence             Displays a sequence number before each packet.
	-S, --size=<size>          Sets the maximum packet size to <size>. Default is 65535.
	-t, --no-timestamp         Do not display a timestamp before each packet.
```

# License
[MIT License](LICENSE)
