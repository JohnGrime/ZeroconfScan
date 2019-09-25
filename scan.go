package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	read_timeout_s = 1
)

var (
	list_  = flag.Bool("list", false, "List system interfaces then exit.")
	timeout_  = flag.Int("timeout", 0, "Duration of scan in seconds (default: 0, no timeout).")
	interfaces_  = flag.String("interfaces", "", "Comma separated list of interfaces to use (default: all, see \"list\").")
)


// Passed through message loop output channels

type DNSMsgInfo struct {
	iface *net.Interface // source interface
	peer net.Addr        // peer who passed this message to us
	src, dst net.IP      // source and destination IP
	msg DNSMessage       // mDNS message
}

// Print information about the local machine's network interfaces

func printNetworkInterfaces() {
	ifaces, err := net.Interfaces()
	if(err != nil) { log.Fatal(err) }

	if len(ifaces)<1 {
		log.Println("No network interfaces found.")
		return
	}

	hostname, _ := os.Hostname()
	log.Println( "Network interfaces for " + hostname )

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if(err != nil) { log.Fatal(err) }

		if len(addrs) < 1 { continue }

		log.Println("-", iface.Name, iface.HardwareAddr)

		for _, addr := range addrs {
			switch v := addr.(type) {
				case *net.IPNet:
					log.Printf("  IPNet: IP=%s, mask=%s, network=%s, %s",
						v.IP, v.Mask, v.Network(), v.String())

				case *net.IPAddr:
					log.Printf("  IPAddr: IP=%s, zone=%s, network=%s, %s",
						v.IP, v.Zone, v.Network(), v.String())

				default:
					log.Println("<unknown>")
			}
		}
	}
}

// IPv4 message loop

func ip4_msg_loop(
	listen_addr *net.UDPAddr,
	mdns_addr *net.UDPAddr,
	ifaces []net.Interface,
	stop_channel chan bool,
	dnsi_channel chan DNSMsgInfo) {
	
	// Listen for UDP packets, bound on the specified address/port
	c, err := net.ListenUDP("udp4", listen_addr)
	if(err != nil) { log.Fatal(err) }
	defer c.Close()

	p := ipv4.NewPacketConn(c)

	// Join multicast groups on appropriate interfaces
	n_joined := 0
	for _,iface := range(ifaces) {
		log.Printf("Joining IPv4 group %s on interface %s (%s flags=%s)...\n",
			mdns_addr, iface.Name,
			iface.HardwareAddr, iface.Flags)

		// Can go wrong with e.g. awdl0 (Apple Wireless Direct Link); we
		// we therefore allow errors here.
		err = p.JoinGroup(&iface, mdns_addr)
		if err != nil {
			log.Printf("Unable to join IPv4 group on interface %s; ignoring", iface.Name);
		} else {
			defer p.LeaveGroup(&iface, mdns_addr)
			n_joined += 1
		}
	}

	if n_joined < 1 {
		log.Println("Unable to join IPv4 groups on any of the specified interfaces")
		return
	}

	// Ensure source and destination addresses included with message
	err = p.SetControlMessage(ipv4.FlagDst, true)
	if(err != nil) { log.Fatal(err) }

	// Buffer for the message data
	b := make([]byte, 1500)

	for {

		dnsi := DNSMsgInfo {}

		select {
			case <-stop_channel:
				log.Println("IPv4 message loop closing")
				return

			default:
				p.SetReadDeadline(time.Now().Add(time.Second*read_timeout_s))
				n, cm, peer, err := p.ReadFrom(b)
				if err != nil {
					if err, ok := err.(net.Error); ok && err.Timeout() {
						// timeout; should be okay.
						continue
					}
					log.Fatal(err)		
				}

				if !cm.Dst.IsMulticast() || !cm.Dst.Equal(mdns_addr.IP) {
					continue // applies to enclosing for{}, not select{}
				}

				iface, err := net.InterfaceByIndex(cm.IfIndex)
				if(err != nil) { log.Fatal(err) }

				dnsi = DNSMsgInfo {
					iface: iface,
					peer: peer,
					src: cm.Src,
					dst: cm.Dst,
				}
				dnsi.msg.FromBytes(b[:n])
				dnsi_channel<- dnsi
		}
	}	
}

// IPv6 message loop

func ip6_msg_loop(
	listen_addr *net.UDPAddr,
	mdns_addr *net.UDPAddr,
	ifaces []net.Interface,
	stop_channel chan bool,
	dnsi_channel chan DNSMsgInfo) {
	
	// Listen for UDP packets, bound on the specified address/port
	c, err := net.ListenUDP("udp6", listen_addr)
	if(err != nil) { log.Fatal(err) }
	defer c.Close()

	p := ipv6.NewPacketConn(c)

	// Join multicast groups on appropriate interfaces
	n_joined := 0
	for _,iface := range(ifaces) {
		log.Printf("Joining IPv6 group %s on %s (%s flags=%s)...\n",
			mdns_addr, iface.Name,
			iface.HardwareAddr, iface.Flags)

		// Can go wrong with e.g. awdl0 (Apple Wireless Direct Link); we
		// we therefore allow errors here.
		err = p.JoinGroup(&iface, mdns_addr)
		if err != nil {
			log.Printf("Unable to join IPv6 group %s; ignoring", iface.Name);
		} else {
			defer p.LeaveGroup(&iface, mdns_addr)
			n_joined += 1
		}
	}

	if n_joined < 1 {
		log.Println("Unable to join IPv6 groups on any of the specified interfaces")
		return
	}

	// Ensure source and destination addresses included with message
	err = p.SetControlMessage(ipv6.FlagDst, true)
	if(err != nil) { log.Fatal(err) }

	// Buffer for the message data
	b := make([]byte, 1500)

	for {

		dnsi := DNSMsgInfo {}

		select {
			case <-stop_channel:
				log.Println("IPv6 message loop closing")
				return

			default:
				p.SetReadDeadline(time.Now().Add(time.Second*read_timeout_s))
				n, cm, peer, err := p.ReadFrom(b)
				if err != nil {
					if err, ok := err.(net.Error); ok && err.Timeout() {
						// timeout; should be okay.
						continue
					}
					log.Fatal(err)		
				}

				if !cm.Dst.IsMulticast() || !cm.Dst.Equal(mdns_addr.IP) {
					continue
				}

				iface, err := net.InterfaceByIndex(cm.IfIndex)
				if(err != nil) { log.Fatal(err) }

				dnsi = DNSMsgInfo {
					iface: iface,
					peer: peer,
					src: cm.Src,
					dst: cm.Dst,
				}
				dnsi.msg.FromBytes(b[:n])
				dnsi_channel<- dnsi
		}
	}	
}

// Main program starts here

func main() {

	var all_ifaces, ifaces []net.Interface
	var err error

	flag.Parse()

	if *list_ == true {
		printNetworkInterfaces()
		return
	}

	timeout_seconds := *timeout_

	// Determine appropriate interfaces

	if (*interfaces_ != "") && (*interfaces_ != "all") {
		substrings := strings.Split(*interfaces_, ",")
		if len(substrings)<1 {
			log.Fatal("No interfaces specified")
		}

		for _,substr := range(substrings) {
			iface, err := net.InterfaceByName(substr)
			if(err != nil) { log.Fatal(err) }
			blah := *iface
			all_ifaces = append(all_ifaces, blah)
		}
	} else {
		all_ifaces, err = net.Interfaces()
		if(err != nil) { log.Fatal(err) }
	}


	for _,iface := range(all_ifaces) {

		// Any addresses assigned?
		addrs, err := iface.Addrs()
		if(err != nil) { log.Fatal(err) }

		if len(addrs) < 1 { continue }

		// Check this interface supports multicast
		if (iface.Flags & net.FlagMulticast) != net.FlagMulticast {
			continue
		}

		ifaces = append(ifaces, iface)
	}

	if len(ifaces)<1 {
		log.Println("No suitable network interfaces found.")
		return
	}

	// Channels to:
	// - collect message loop output
	// - signal message loops to stop

	mdns_chan := make(chan DNSMsgInfo)
	stop_chan := make(chan bool)

	// Launch message loops

	wait_group := sync.WaitGroup{}

	wait_group.Add(1)
	go func() {
		defer wait_group.Done()

		mDNSAddr4, err := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
		if err != nil { log.Fatal(err) }

		ip4_msg_loop(mDNSAddr4, mDNSAddr4, ifaces, stop_chan, mdns_chan)
	}()
	
	wait_group.Add(1)
	go func() {
		defer wait_group.Done()

		mDNSAddr6, err := net.ResolveUDPAddr("udp6", "[ff02::fb]:5353")
		if err != nil { log.Fatal(err) }

		ip6_msg_loop(mDNSAddr6, mDNSAddr6, ifaces, stop_chan, mdns_chan)
	}()

	// Install signal handler and timeout

	interrupt_chan := make(chan os.Signal, 1)
	signal.Notify(interrupt_chan, os.Interrupt, syscall.SIGTERM)

	timeout_chan := make(<-chan time.Time);
	if timeout_seconds > 0 {
		timeout_chan = time.After(time.Second * time.Duration(timeout_seconds))
	}

	// Monitor stop channels

	for {

		should_quit := false

		select {
			case <-interrupt_chan:
				log.Println("Interrupted")
				should_quit = true

			case <-timeout_chan:
				log.Println("Timeout")
				should_quit = true

			case dnsi := <-mdns_chan:
				log.Printf("%+s -> %+s (from peer %s, intf=%s)\n",
					dnsi.src, dnsi.dst,
					dnsi.peer, dnsi.iface.Name )
				dnsi.msg.Print()
		}

		if should_quit { break }
	}

	log.Println("Closing message loop channels")
	close(stop_chan)

	// Read from message queue until it closes. This avoid hangs where someone
	// tries to write to the message channel after we stopped reading from it.

	go func() {
		log.Println("Started pumping message queue")
		for {
			_,ok := <-mdns_chan
			if ok == false { break }
		}
		log.Println("Stopped pumping message queue")
	}()

	// Wait for message loops to exit cleanly

	log.Println("Waiting for message routine completion")
	wait_group.Wait()

	// Close message channel, which should also stop the pump goroutine.

	log.Println("Closing message loop output channel")
	close(mdns_chan)
	log.Println("Message loop output channel closed")
}
