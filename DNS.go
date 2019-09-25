package main

/*
	Basic DNS message structure:

	DNSMessage {
		Header:     {Id, Flags, nQuestion, nAnswer, nAuthority, nAdditional}
		Question:   [ DNSRRHeader, ... ]
		Answer:     [ DNSRR, ... ]
		Authority:  [ DNSRR, ... ]
		Additional: [ DNSRR, ... ]
	}

	Here, DNSRR = {DNSRRHeader, TTL, Payload} with "Payload" a
	PTR, SRV, TXT etc structure.
*/

import (
	"fmt"
	"net"
	"strings"

	"encoding/binary"
)

const (
	// Message header flag bitmasks; e.g. RFC1035:4.1.1
	QRMask uint16 = 1 << 15  // 0b1000000000000000
	OpMask uint16 = 15 << 11 // 0b0111100000000000
	AAMask uint16 = 1 << 10  // 0b0000010000000000
	TCMask uint16 = 1 << 9   // 0b0000001000000000
	RDMask uint16 = 1 << 8   // 0b0000000100000000
	RAMask uint16 = 1 << 7   // 0b0000000010000000
	ZrMask uint16 = 1 << 6   // 0b0000000001000000
	ADMask uint16 = 1 << 5   // 0b0000000000100000
	CDMask uint16 = 1 << 4   // 0b0000000000010000
	RcMask uint16 = 15       // 0b0000000000001111

	// OpCodes, no obsolete/removed/unassigned; RFC6895
	QUERY  uint16 = 0
	STATUS uint16 = 2
	NOTIFY uint16 = 4
	UPDATE uint16 = 5
	DSO    uint16 = 6

	// Rcodes, no unassigned/reserved; RFC1035:4.1.1, ignores 6895:2.3
	NOERROR  uint16 = 0
	FORMERR  uint16 = 1
	SERVFAIL uint16 = 2
	NXDOMAIN uint16 = 3
	NOTIMP   uint16 = 4
	REFUSED  uint16 = 5
	YXDOMAIN uint16 = 6
	YXRRSET  uint16 = 7
	NXRRSET  uint16 = 8
	NOTAUTH  uint16 = 9
	NOTZONE  uint16 = 10

	// Types, no obsolete/experimental; RFC1035:3.2.2, 3596:2.1, 2782:1.1
	A     uint16 = 1
	NS    uint16 = 2
	CNAME uint16 = 5
	SOA   uint16 = 6
	NULL  uint16 = 10
	WKS   uint16 = 11
	PTR   uint16 = 12
	HINFO uint16 = 13
	MINFO uint16 = 14
	MX    uint16 = 15
	TXT   uint16 = 16
	AAAA  uint16 = 28
	SRV   uint16 = 33
	ANY   uint16 = 255

	// Classes, "no obsolete" ;) RFC1035:3.2.4
	IN uint16 = 1
	CH uint16 = 3
	HS uint16 = 4
)

var (
	OpCodeToText = map[uint16]string {
		QUERY:  "QUERY",
		STATUS: "STATUS",
		NOTIFY: "NOTIFY",
		UPDATE: "UPDATE",
		DSO:    "DSO",
	}

	RcodeToText = map[uint16]string {
		NOERROR:  "NOERROR",
		FORMERR:  "FORMERR",
		SERVFAIL: "SERVFAIL",
		NXDOMAIN: "NXDOMAIN",
		NOTIMP:   "NOTIMP",
		REFUSED:  "REFUSED",
		YXDOMAIN: "YXDOMAIN",
		YXRRSET:  "YXRRSET",
		NXRRSET:  "NXRRSET",
		NOTAUTH:  "NOTAUTH",
		NOTZONE:  "NOTZONE",
	}

	TypeToString = map[uint16]string {
		A:     "A",
		NS:    "NS",
		CNAME: "CNAME",
		SOA:   "SOA",
		NULL:  "NULL",
		WKS:   "WKS",
		PTR:   "PTR",
		HINFO: "HINFO",
		MINFO: "MINFO",
		MX:    "MX",
		TXT:   "TXT",
		AAAA:  "AAAA",
		SRV:   "SRV",
		ANY:   "ANY",
	}

	ClassToString = map[uint16]string {
		IN: "IN",
		CH: "CH",
		HS: "HS",
	}
)

// For the "Flags" member of MessageHeader; RFC1035:4.1.1

func IsResponse(u uint16) bool {
	return (u & QRMask) == QRMask
}

func OpCode(u uint16) uint16 {
	return (u & OpMask) >> 11
}

func IsAuthoritative(u uint16) bool {
	return (u & AAMask) == AAMask
}

func IsTruncated(u uint16) bool {
	return (u & TCMask) == TCMask
}

func IsRecursionDesired(u uint16) bool {
	return (u & RDMask) == RDMask
}

func IsRecursionAvailable(u uint16) bool {
	return (u & RAMask) == RAMask
}

func IsAuthenticatedData(u uint16) bool {
	return (u & ADMask) == ADMask
}

func IsCheckingDisabled(u uint16) bool {
	return (u & CDMask) == CDMask
}

func Rcode(u uint16) uint16 {
	return (u & RcMask)
}

// Parse byte sequence of [N][b1,b2,...bN] into labels; RFC1035:2.3.4,3.1
// allow_ptr flag determines whether we follow "pointers" for compression.
func parse_labels(i int, max_i int, b []byte, allow_ptr bool) (int,[]string) {

	ptr_bits := uint8(0xc0)    // 0b11000000
	idx_bits := uint16(0x3FFF) // 0b0011111111111111

	var results = []string{}
	
	for {

		if (max_i>0) && (i>=max_i) { return max_i+1, results }

		if (allow_ptr) && ((b[i]&ptr_bits)==ptr_bits) {
			u16 := binary.BigEndian.Uint16(b[i:]) & idx_bits
			i += 2
			_, new_results := parse_labels(int(u16),max_i,b,allow_ptr)
			return i, append(results, new_results...)
		} else {
			l := int(b[i])
			i += 1
			if l == 0 { return i, results }
			new_string := string(b[i:i+l])
			results = append(results, new_string)
			i += l
		}
	}
}

// DNS resource record header (also forms complete entry for question section)

type DNSRRHeader struct {
	Name string
	Type uint16
	Class uint16
}

func (h *DNSRRHeader) FromBytes(i int, b []byte) int {
	var l []string

	i, l = parse_labels(i,-1,b,true)
	h.Name = strings.Join(l,".")

	h.Type = binary.BigEndian.Uint16(b[i:])
	i += 2

	h.Class = binary.BigEndian.Uint16(b[i:])
	i += 2

	return i
}

// DNS resource record

type DNSRR struct {
	Header DNSRRHeader
	TTL uint32
	Payload interface{} // set after reading header

	// For debug and future inspection
	raw_payload []byte
}

func (rr *DNSRR) FromBytes(i int, b []byte) int {
	i = rr.Header.FromBytes(i,b)

	rr.TTL = binary.BigEndian.Uint32(b[i:])
	i += 4

	rdlen := int( binary.BigEndian.Uint16(b[i:]) )
	i += 2

	rr.raw_payload = b[i:i+rdlen] // slice backed by parent message's RawMessage

	var l = []string{}

	switch rr.Header.Type {
		case A:
			rr.Payload = DNSPayloadA {
				IP: net.IPv4(b[i+0],b[i+1],b[i+2],b[i+3]), // FIX THIS: BOUNDS CHECK
			}

		case PTR:
			_,l = parse_labels(i, i+rdlen, b, true)
			rr.Payload = DNSPayloadPtr{
				Text: strings.Join(l, "."),
			}

		case TXT:
			_,l = parse_labels(i, i+rdlen, b, false)
			rr.Payload = DNSPayloadTxt{
				Text: strings.Join(l, " "),
			}

		case AAAA:
			rr.Payload = DNSPayloadAAAA {
				IP: b[i:i+16], // FIX THIS: BOUNDS CHECK
			}

		case SRV:
			_,l = parse_labels(i+6, i+rdlen, b, true) // i+6: labels @ i+(3xU16)
			rr.Payload = DNSPayloadSrv{
				Priority: binary.BigEndian.Uint16(b[i:]),
				Weight: binary.BigEndian.Uint16(b[i+2:]),
				Port: binary.BigEndian.Uint16(b[i+4:]),
				Text: strings.Join(l, " "),
			}
	}

	i += rdlen

	return i
}

// DNS resource record "payloads" - type specific data for rr's

// RFC1025 3.4.1
type DNSPayloadA struct {
	IP net.IP
}

// RFC3596  2.2
type DNSPayloadAAAA struct {
	IP net.IP
}

// RFC1035 3.3.12
type DNSPayloadPtr struct {
	Text string
}

// RFC1035 3.3.14
type DNSPayloadTxt struct {
	Text string
}

// RFC2782
type DNSPayloadSrv struct {
	Priority uint16
	Weight uint16
	Port uint16
	Text string
}

// DNS message header

type DNSMessageHeader struct {
	Identification uint16
	Flags uint16
	QuestionCount uint16
	AnswerCount uint16
	AuthorityCount uint16
	AdditionalCount uint16
}

func (h *DNSMessageHeader) FromBytes(i int, b []byte) int {
	ptrs := []*uint16 {
		&h.Identification, &h.Flags,
		&h.QuestionCount, &h.AnswerCount,
		&h.AuthorityCount, &h.AdditionalCount,
	}

	for _,ptr := range(ptrs) {
		*ptr = binary.BigEndian.Uint16(b[i:])
		i += 2
	}

	return i
}

func (h *DNSMessageHeader) String() string {

	oc, rc := "UNASSIGNED", "UNASSIGNED"
	oc, _ = OpCodeToText[OpCode(h.Flags)]
	rc, _ = RcodeToText[Rcode(h.Flags)]
	s := fmt.Sprintf("%s %s", oc, rc)

	if IsResponse(h.Flags) { s += " response" }
	if IsAuthoritative(h.Flags) { s += " authoritative" }
	if IsTruncated(h.Flags) { s += " truncated" }
	if IsRecursionDesired(h.Flags) { s += " recursion_desired" }
	if IsRecursionAvailable(h.Flags) { s += " recursion_available" }
	if IsAuthenticatedData(h.Flags) { s += " authenticated" }
	if IsCheckingDisabled(h.Flags) { s += " checking_disabled" }

	return fmt.Sprintf( "ID:%d Flags:{%s} Question:%d Answer:%d Authority:%d Additional:%d",
		h.Identification, s, h.QuestionCount, h.AnswerCount, h.AuthorityCount, h.AdditionalCount )
}

// DNS message

type DNSMessage struct {
	Header DNSMessageHeader
	Question []DNSRRHeader
	Answer, Authority, Additional []DNSRR

	// For denug and future inspection
	raw_msg []byte
}

func (m *DNSMessage) FromBytes(bytes []byte) {
	m.raw_msg = make([]byte, len(bytes))
	copy(m.raw_msg, bytes)

	i := m.Header.FromBytes(0,m.raw_msg)

	for j := uint16(0); j<m.Header.QuestionCount; j++ {
		h := DNSRRHeader{}
		i = h.FromBytes(i,m.raw_msg)
		m.Question = append(m.Question, h)
	}

	for j := uint16(0); j<m.Header.AnswerCount; j++ {
		rr := DNSRR{}
		i = rr.FromBytes(i,m.raw_msg)
		m.Answer = append(m.Answer, rr)
	}

	for j := uint16(0); j<m.Header.AuthorityCount; j++ {
		rr := DNSRR{}
		i = rr.FromBytes(i,m.raw_msg)
		m.Authority = append(m.Authority, rr)
	}

	for j := uint16(0); j<m.Header.AdditionalCount; j++ {
		rr := DNSRR{}
		i = rr.FromBytes(i,m.raw_msg)
		m.Additional = append(m.Additional, rr)
	}
}

func (m *DNSMessage) Print() {
	indent := "  "
	indentx2 := indent+indent

	fmt.Println(indent+"Header:")
	fmt.Println(indentx2, m.Header.String() )

	if len(m.Question)>0 {
		fmt.Println(indent+"Questions:")
		for _,h := range(m.Question) {
			rr_print(indentx2, &h)
		}
	}

	if len(m.Answer)>0 {
		fmt.Println(indent+"Answers:")
		for _,rr := range(m.Answer) {
			rr_print(indentx2, &rr)
		}
	}

	if len(m.Authority)>0 {
		fmt.Println(indent+"Authority:")
		for _,rr := range(m.Authority) {
			rr_print(indentx2, &rr)
		}
	}

	if len(m.Additional)>0 {
		fmt.Println(indent+"Additional:")
		for _,rr := range(m.Additional) {
			rr_print(indentx2, &rr)
		}
	}
	fmt.Println()
}

// Misc. internal

func rr_print(preamble string, in interface{}) {
	var hdr *DNSRRHeader
	t, ttl, p := "", "", ""

	switch x := in.(type) {
		case *DNSRRHeader:
			hdr = x
			switch x.Type {
				case A:
					t = fmt.Sprintf("A   ")

				case AAAA:
					t = fmt.Sprintf("AAAA")

				case PTR:
					t = fmt.Sprintf("PTR ")

				case TXT:
					t = fmt.Sprintf("TXT ")

				case SRV:
					t = fmt.Sprintf("SVR ")

				default:
					t = fmt.Sprintf("UNK ")
			}

		case *DNSRR:
			hdr = &x.Header
			// Can use Type in header as above, but this shows how to determine payload type
			switch payload := x.Payload.(type) {
				case DNSPayloadA:
					t, p = fmt.Sprintf("A   "), fmt.Sprintf(", payload=%+v", payload)

				case DNSPayloadAAAA:
					t, p = fmt.Sprintf("AAAA"), fmt.Sprintf(", payload=%+v", payload)

				case DNSPayloadPtr:
					t, p = fmt.Sprintf("PTR "), fmt.Sprintf(", payload=%+v", payload)

				case DNSPayloadTxt:
					t, p = fmt.Sprintf("TXT "), fmt.Sprintf(", payload=%+v", payload)

				case DNSPayloadSrv:
					t, p = fmt.Sprintf("SVR "), fmt.Sprintf(", payload=%+v", payload)

				default:
					t, p = fmt.Sprintf("UNK "), fmt.Sprintf(", payload={%d bytes rdata}", len(x.raw_payload))
			}
			ttl = fmt.Sprintf("%-10s", fmt.Sprintf("TTL=%d ",x.TTL))
	}

	fmt.Printf("%s%s %sheader={type=%s class=%s name='%s'}%s\n",
		preamble, t, ttl,
		fmt.Sprintf("%-10s", fmt.Sprintf("%d (%s)", hdr.Type, TypeToString[hdr.Type])),
		fmt.Sprintf("%-10s", fmt.Sprintf("%d (%s)", hdr.Class, ClassToString[hdr.Class])),
		hdr.Name, p)

}
