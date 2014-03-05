package main

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/miekg/dns"
)

func main() {
	c := new(dns.Client)
	c.Net = "tcp"
	m := new(dns.Msg)
	m.SetQuestion("direct1.demo.direct-test.com.", dns.TypeCERT)
	in, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		fmt.Println("ERROR: ", err)
		return
	}
	fmt.Println("MsgHdr: ", in.MsgHdr)
	if in.MsgHdr.Rcode != 0 {
		fmt.Println("ERROR from DNS server: ",
			dns.RcodeToString[in.MsgHdr.Rcode])
		return
	}
	fmt.Println("Length of answer: ", len(in.Answer))
	if rr, ok := in.Answer[0].(*dns.CERT); ok {
		fmt.Println(rr.Type, rr.KeyTag, rr.Algorithm, rr.Certificate)
		asn, err := base64.StdEncoding.DecodeString(rr.Certificate)
		if err != nil {
			fmt.Println("Error b64 decoding: ", err)
			return
		}
		cert, err := x509.ParseCertificate(asn)
		if err != nil {
			fmt.Println("Error decoding cert: ", err)
			return
		}
		fmt.Println(cert.Subject)
		fmt.Println(cert.DNSNames)
		fmt.Println(cert.EmailAddresses)

	}
}
