package main

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

func GetNameString(names []pkix.AttributeTypeAndValue) string {
	var b bytes.Buffer

	for _, v := range names {
		b.WriteString("/")
		b.WriteString(getTagForOid(v.Type))
		b.WriteString("=")
		b.WriteString(fmt.Sprint(v.Value))
	}

	return b.String()
}

func getTagForOid(oid asn1.ObjectIdentifier) string {
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
