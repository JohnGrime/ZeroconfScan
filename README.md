# ZerconfScan

A Zerconf/mDNS message sniffer in Go using IPv4 and IPv6. Self-contained; uses no external libraries.

## Example usage

For simplicity, all examples use Go's `run` option.

### Get help

Run the program with the `--help` command line switch to see options:

```
Me$ go run . --help
Usage of /var/folders/7n/c44rpgrx2v533glf8c_zss_8ynhhl2/T/go-build977439345/b001/exe/DNS:
  -interfaces string
    	Comma separated list of interfaces to use (default: all, see "list").
  -list
    	List system interfaces then exit.
  -timeout int
    	Duration of scan in seconds (default: 0, no timeout).
exit status 2
```

### List available network interfaces

To list all available interfaces on the current machine (in this case, an iMac), we would therefore try:

```
Me$ go run . --list
2019/09/25 13:15:05 Network interfaces for XXX
2019/09/25 13:15:05 - lo0 
2019/09/25 13:15:05   IPNet: IP=127.0.0.1, mask=ff000000, network=ip+net, 127.0.0.1/8
2019/09/25 13:15:05   IPNet: IP=::1, mask=ffffffffffffffffffffffffffffffff, network=ip+net, ::1/128
2019/09/25 13:15:05   IPNet: IP=fe80::1, mask=ffffffffffffffff0000000000000000, network=ip+net, fe80::1/64
2019/09/25 13:15:05 - en0 xx:xx:xx:xx:xx:xx
2019/09/25 13:15:05   IPNet: IP=fe80:etc, mask=ffffffffffffffff0000000000000000, network=ip+net, fe80:etc
2019/09/25 13:15:05   IPNet: IP=10.etc, mask=fffff800, network=ip+net, 10.etc/21
2019/09/25 13:15:05 - en1 xx:xx:xx:xx:xx:xx
2019/09/25 13:15:05   IPNet: IP=fe80:etc, mask=ffffffffffffffff0000000000000000, network=ip+net, fe80:etc
2019/09/25 13:15:05   IPNet: IP=10.etc, mask=fffff000, network=ip+net, 10.etc/20
2019/09/25 13:15:05 - awdl0 xx:xx:xx:xx:xx:xx
2019/09/25 13:15:05   IPNet: IP=fe80:etc, mask=ffffffffffffffff0000000000000000, network=ip+net, fe80:etc/64
2019/09/25 13:15:05 - utun0 
2019/09/25 13:15:05   IPNet: IP=fe80:etc, mask=ffffffffffffffff0000000000000000, network=ip+net, fe80:etc
```

### Simple scanning

By default, scanning is by default performed using all appropriate network interfaces:

```
Me$ go run .
2019/09/25 13:18:51 Joining IPv4 group 224.0.0.251:5353 on interface lo0 ( flags=up|loopback|multicast)...
2019/09/25 13:18:51 Joining IPv6 group [ff02::fb]:5353 on lo0 ( flags=up|loopback|multicast)...
2019/09/25 13:18:51 Joining IPv4 group 224.0.0.251:5353 on interface en0 (xx:xx:xx:xx:xx:xx flags=up|broadcast|multicast)...
2019/09/25 13:18:51 Joining IPv6 group [ff02::fb]:5353 on en0 (xx:xx:xx:xx:xx:xx flags=up|broadcast|multicast)...
2019/09/25 13:18:51 Joining IPv6 group [ff02::fb]:5353 on en1 (xx:xx:xx:xx:xx:xx flags=up|broadcast|multicast)...
2019/09/25 13:18:51 Joining IPv4 group 224.0.0.251:5353 on interface en1 (xx:xx:xx:xx:xx:xx flags=up|broadcast|multicast)...
2019/09/25 13:18:51 Joining IPv6 group [ff02::fb]:5353 on awdl0 (xx:xx:xx:xx:xx:xx flags=up|broadcast|multicast)...
2019/09/25 13:18:51 Joining IPv4 group 224.0.0.251:5353 on interface awdl0 (xx:xx:xx:xx:xx:xx flags=up|broadcast|multicast)...
2019/09/25 13:18:51 Joining IPv6 group [ff02::fb]:5353 on utun0 ( flags=up|pointtopoint|multicast)...
2019/09/25 13:18:51 Unable to join IPv4 group on interface awdl0; ignoring
2019/09/25 13:18:51 Joining IPv4 group 224.0.0.251:5353 on interface utun0 ( flags=up|pointtopoint|multicast)...
2019/09/25 13:18:51 10.etc -> 224.0.0.251 (from peer 10.etc:5353, intf=en0)
  Header:
     ID:0 Flags:{QUERY NOERROR} Question:1 Answer:0 Authority:0 Additional:0
  Questions:
    PTR  header={type=12 (PTR)   class=1 (IN)     name='_apple-mobdev2._tcp.local'}

2019/09/25 13:18:51 fe80:etc -> ff02::fb (from peer [fe80:etc%en0]:5353, intf=en0)
  Header:
     ID:0 Flags:{QUERY NOERROR} Question:1 Answer:0 Authority:0 Additional:0
  Questions:
    PTR  header={type=12 (PTR)   class=1 (IN)     name='_apple-mobdev2._tcp.local'}

2019/09/25 13:18:51 10.etc -> 224.0.0.251 (from peer 10.etc:5353, intf=en0)
  Header:
     ID:0 Flags:{QUERY NOERROR} Question:2 Answer:0 Authority:0 Additional:0
  Questions:
    SVR  header={type=33 (SRV)   class=1 (IN)     name='Brother MFC-9330CDW [9c2a7044299c] (2)._pdl-datastream._tcp.local'}
    TXT  header={type=16 (TXT)   class=1 (IN)     name='Brother MFC-9330CDW [9c2a7044299c] (2)._pdl-datastream._tcp.local'}

2019/09/25 13:18:51 fe80:etc -> ff02::fb (from peer [fe80:etc%en0]:5353, intf=en0)
  Header:
     ID:0 Flags:{QUERY NOERROR} Question:2 Answer:0 Authority:0 Additional:0
  Questions:
    SVR  header={type=33 (SRV)   class=1 (IN)     name='Brother MFC-9330CDW [9c2a7044299c] (2)._pdl-datastream._tcp.local'}
    TXT  header={type=16 (TXT)   class=1 (IN)     name='Brother MFC-9330CDW [9c2a7044299c] (2)._pdl-datastream._tcp.local'}

... etc ...
```

### Other scanning options

The program can also be run with a timeout specified in seconds (`--timeout=x`), and/or a set of specific network interfaces:

```
Me$ go run . --timeout 5 --interfaces=en0,en1
2019/09/25 13:22:55 Joining IPv6 group [ff02::fb]:5353 on en0 (xx.xx.xx.xx.xx.xx flags=up|broadcast|multicast)...
2019/09/25 13:22:55 Joining IPv4 group 224.0.0.251:5353 on interface en0 (xx.xx.xx.xx.xx.xx flags=up|broadcast|multicast)...
2019/09/25 13:22:55 Joining IPv6 group [ff02::fb]:5353 on en1 (xx.xx.xx.xx.xx.xx flags=up|broadcast|multicast)...
2019/09/25 13:22:55 Joining IPv4 group 224.0.0.251:5353 on interface en1 (xx.xx.xx.xx.xx.xx flags=up|broadcast|multicast)...
2019/09/25 13:22:55 10.etc -> 224.0.0.251 (from peer 10.etc:5353, intf=en0)

... etc ...

2019/09/25 13:23:00 Timeout
2019/09/25 13:23:00 Closing message loop channels
2019/09/25 13:23:00 Started pumping message queue
2019/09/25 13:23:00 Waiting for message routine completion
2019/09/25 13:23:00 IPv4 message loop closing
2019/09/25 13:23:00 IPv6 message loop closing
2019/09/25 13:23:00 Closing message loop output channel
2019/09/25 13:23:00 Message loop output channel closed
2019/09/25 13:23:00 Stopped pumping message queue
```
