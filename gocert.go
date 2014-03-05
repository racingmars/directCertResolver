package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"github.com/miekg/dns"
)

func main() {
	c := new(dns.Client)
	c.Net = "tcp"
	m := new(dns.Msg)
	m.SetQuestion("direct1.demo.direct-test.com.", dns.TypeCERT)
	//m.SetQuestion("kryptiq.direct-ci.com.", dns.TypeCERT)
	in, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		fmt.Println("ERROR: ", err)
		return
	}
	//fmt.Println("MsgHdr: ", in.MsgHdr)
	if in.MsgHdr.Rcode != 0 {
		fmt.Println("ERROR from DNS server: ",
			dns.RcodeToString[in.MsgHdr.Rcode])
		return
	}
	//fmt.Println("Length of answer: ", len(in.Answer))
	if rr, ok := in.Answer[0].(*dns.CERT); ok {
		//fmt.Println(rr.Type, rr.KeyTag, rr.Algorithm, rr.Certificate)
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
		//fmt.Println(cert.Subject)
		//fmt.Println(cert.DNSNames)
		//fmt.Println(cert.EmailAddresses)
		//fmt.Println("--- Subject ---")
		//fmt.Println(cert.Subject.SerialNumber)

		/*for _, v := range cert.Subject.Names {
			fmt.Println(v)
		}

		fmt.Println("--- Issuer ---")
		for _, v := range cert.Issuer.Names {
			fmt.Println(v)
		}*/

		fmt.Println("Subject: ", GetNameString(cert.Subject.Names))
		fmt.Println("Issuer: ", GetNameString(cert.Issuer.Names))
	}
}

func GetNameString(names []pkix.AttributeTypeAndValue) string {
	var b bytes.Buffer

	for _, v := range names {
		b.WriteString("/")
		b.WriteString(GetTagForOid(v.Type))
		b.WriteString("=")
		b.WriteString(fmt.Sprint(v.Value))
	}

	return b.String()
}

func GetTagForOid(oid asn1.ObjectIdentifier) string {
	type oidNameMap struct {
		oid  []int
		name string
	}

	oidTags := []oidNameMap{
		{[]int{2, 5, 4, 3}, "CN"},
		{[]int{2, 5, 4, 5}, "SN"},
		{[]int{2, 5, 4, 6}, "C"},
		{[]int{2, 5, 4, 7}, "L"},
		{[]int{2, 5, 4, 8}, "ST"},
		{[]int{2, 5, 4, 10}, "O"},
		{[]int{2, 5, 4, 11}, "OU"},
		{[]int{1, 2, 840, 113549, 1, 9, 1}, "E"}}

	for _, v := range oidTags {
		if oid.Equal(v.oid) {
			return v.name
		}
	}

	return fmt.Sprint(oid)

}
