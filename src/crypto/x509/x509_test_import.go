// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

// This file is run by the x509 tests to ensure that a program with minimal
// imports can sign certificates without errors resulting from missing hash
// functions.
package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"time"
)

func main() {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	rsaPriv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic("Failed to parse private key: " + err.Error())
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test",
			Organization: []string{"Σ Acme Co"},
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),
		KeyUsage:  x509.KeyUsageCertSign,
	}

	if _, err = x509.CreateCertificate(rand.Reader, &template, &template, &rsaPriv.PublicKey, rsaPriv); err != nil {
		panic("failed to create certificate with basic imports: " + err.Error())
	}
}

var pemPrivateKey = testingKey(`-----BEGIN RSA TESTING KEY-----
MIIEpAIBAAKCAQEAn/H5NDeonggV+CDlSHyorbeJBnDkC3opgn7I6qh3MrDCFRhL
RUjOhOAMteNX/+yKnVtFLSKjW+D14UTiA+8g8UdvOMS+l2wrr/7eYT91HHoWHN4Z
i4slXTJGUImVrX1FCX/9ajrTPqITYOfS0VqeHfuol9JWtSS9xMAiHJJDYyfYUGxe
z29gkvhEvWKOeSgGqfCjm5aXEfDAUjd/G6p8I30HQl7zhDo2pth1MSsxBV+TAPnw
NJnuAoqAnAkS1ipfhqDfRfHwAX6Gfk/tnmpeAy7jvea10fEqziFQYd1xTq/0VYY7
V3DVRWSnLw7enevFeowCgGCpuZ5Y/Rj6XeL/qwIDAQABAoIBAQCNpMZifd/vg42h
HdCvLuZaYS0R7SunFlpoXEsltGdLFsnp0IfoJZ/ugFQBSAIIfLwMumU6oXA1z7Uv
98aIYV61DePrTCDVDFBsHbNmP8JAo8WtbusEbwd5zyoB7LYG2+clkJklWE73KqUq
rmI+UJeyScl2Gin7ZTxBXz1WPBk9VwcnwkeaXpgASIBW23fhECM9gnYEEwaBez5T
6Me8d1tHtYQv7vsKe7ro9w9/HKrRXejqYKK1LxkhfFriyV+m8LZJZn2nXOa6G3gF
Nb8Qk1Uk5PUBENBmyMFJhT4M/uuSq4YtMrrO2gi8Q+fPhuGzc5SshYKRBp0W4P5r
mtVCtEFRAoGBAMENBIFLrV2+HsGj0xYFasKov/QPe6HSTR1Hh2IZONp+oK4oszWE
jBT4VcnITmpl6tC1Wy4GcrxjNgKIFZAj+1x1LUULdorXkuG8yr0tAhG9zNyfWsSy
PrSovC0UVbzr8Jxxla+kQVxEQQqWQxPlEVuL8kXaIDA6Lyt1Hpua2LvPAoGBANQZ
c6Lq2T7+BxLxNdi2m8kZzej5kgzBp/XdVsbFWRlebIX2KrFHsrHzT9PUk3DE1vZK
M6pzTt94nQhWSkDgCaw1SohElJ3HFIFwcusF1SJAc3pQepd8ug6IYdlpDMLtBj/P
/5P6BVUtgo05E4+I/T3iYatmglQxTtlZ0RkSV2llAoGBALOXkKFX7ahPvf0WksDh
uTfuFOTPoowgQG0EpgW0wRdCxeg/JLic3lSD0gsttQV2WsRecryWcxaelRg10RmO
38BbogmhaF4xvgsSvujOfiZTE8oK1T43M+6NKsIlML3YILbpU/9aJxPWy0s2DqDr
cQJhZrlk+pzjBA7Bnf/URdwxAoGAKR/CNw14D+mrL3YLbbiCXiydqxVwxv5pdZdz
8thi3TNcsWC4iGURdcVqbfUinVPdJiXe/Kac3WGCeRJaFVgbKAOxLti1RB5MkIhg
D8eyupBqk4W1L1gkrxqsdj4TFlxkwMywjl2E2S4YyQ8PBt6V04DoVRZsIKzqz+PF
UionPq0CgYBCYXvqioJhPewkOq/Y5wrDBeZW1FQK5QD9W5M8/5zxd4rdvJtjhbJp
oOrtvMdrl6upy9Hz4BJD3FXwVFiPFE7jqeNqi0F21viLxBPMMD3UODF6LL5EyLiR
9V4xVMS8KXxvg7rxsuqzMPscViaWUL6WNVBhsD2+92dHxSXzz5EJKQ==
-----END RSA TESTING KEY-----
`)

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }
