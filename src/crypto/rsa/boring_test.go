// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Note: Can run these tests against the non-BoringCrypto
// version of the code by using "CGO_ENABLED=0 go test".

package rsa

import (
	"crypto"
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"reflect"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"
)

func TestBoringASN1Marshal(t *testing.T) {
	k, err := GenerateKey(rand.Reader, 128)
	if err != nil {
		t.Fatal(err)
	}
	// This used to fail, because of the unexported 'boring' field.
	// Now the compiler hides it [sic].
	_, err = asn1.Marshal(k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBoringDeepEqual(t *testing.T) {
	k, err := GenerateKey(rand.Reader, 128)
	if err != nil {
		t.Fatal(err)
	}
	k.boring = nil // probably nil already but just in case
	k2 := *k
	k2.boring = unsafe.Pointer(k) // anything not nil, for this test
	if !reflect.DeepEqual(k, &k2) {
		// compiler should be hiding the boring field from reflection
		t.Fatalf("DeepEqual compared boring fields")
	}
}

func TestBoringVerify(t *testing.T) {
	// Check that signatures that lack leading zeroes don't verify.
	key := &PublicKey{
		N: bigFromHex("c4fdf7b40a5477f206e6ee278eaef888ca73bf9128a9eef9f2f1ddb8b7b71a4c07cfa241f028a04edb405e4d916c61d6beabc333813dc7b484d2b3c52ee233c6a79b1eea4e9cc51596ba9cd5ac5aeb9df62d86ea051055b79d03f8a4fa9f38386f5bd17529138f3325d46801514ea9047977e0829ed728e68636802796801be1"),
		E: 65537,
	}

	hash := fromHex("019c5571724fb5d0e47a4260c940e9803ba05a44")
	paddedHash := fromHex("3021300906052b0e03021a05000414019c5571724fb5d0e47a4260c940e9803ba05a44")

	// signature is one byte shorter than key.N.
	sig := fromHex("5edfbeb6a73e7225ad3cc52724e2872e04260d7daf0d693c170d8c4b243b8767bc7785763533febc62ec2600c30603c433c095453ede59ff2fcabeb84ce32e0ed9d5cf15ffcbc816202b64370d4d77c1e9077d74e94a16fb4fa2e5bec23a56d7a73cf275f91691ae1801a976fcde09e981a2f6327ac27ea1fecf3185df0d56")

	err := VerifyPKCS1v15(key, 0, paddedHash, sig)
	if err == nil {
		t.Errorf("raw: expected verification error")
	}

	err = VerifyPKCS1v15(key, crypto.SHA1, hash, sig)
	if err == nil {
		t.Errorf("sha1: expected verification error")
	}
}

func TestBoringGenerateKey(t *testing.T) {
	k, err := GenerateKey(rand.Reader, 2048) // 2048 is smallest size BoringCrypto might kick in for
	if err != nil {
		t.Fatal(err)
	}

	// Non-Boring GenerateKey always sets CRTValues to a non-nil (possibly empty) slice.
	if k.Precomputed.CRTValues == nil {
		t.Fatalf("GenerateKey: Precomputed.CRTValues = nil")
	}
}

func TestBoringFinalizers(t *testing.T) {
	if runtime.GOOS == "nacl" || runtime.GOOS == "js" {
		// Times out on nacl and js/wasm (without BoringCrypto)
		// but not clear why - probably consuming rand.Reader too quickly
		// and being throttled. Also doesn't really matter.
		t.Skipf("skipping on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	k, err := GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Run test with GOGC=10, to make bug more likely.
	// Without the KeepAlives, the loop usually dies after
	// about 30 iterations.
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	for n := 0; n < 200; n++ {
		// Clear the underlying BoringCrypto object.
		atomic.StorePointer(&k.boring, nil)

		// Race to create the underlying BoringCrypto object.
		// The ones that lose the race are prime candidates for
		// being GC'ed too early if the finalizers are not being
		// used correctly.
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sum := make([]byte, 32)
				_, err := SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum)
				if err != nil {
					panic(err) // usually caused by memory corruption, so hard stop
				}
			}()
		}
		wg.Wait()
	}
}

// These test vectors were generated with `openssl rsautl -pkcs -encrypt`
var boringDecryptPKCS1v15Tests = []DecryptPKCS1v15Test{
	{
		"lIaBY0iAAXfMTR1cEBZJuAKaU4kbY6lpxwZ7FZ96rRZjJNH08fja/LhuP9W7pkPGFwfcLMaN+hTdLO4jM3xZqRziNAmDYdHiI+o79oh0Z0pIZ15fSmlX07ET/wJAB8qsjR7/OzEBppiv9R87U9RlFkugP+cU0EdPq7ISK+jbO0w0altzZFUCX5z8/m8EABqHqhlq7suZJ7su4oih9BneErf5Xi+NZqwwe8bSdsxN0+Fmmcm7ebOwVJpoRG4c0owbor6Vl/DAJybQR2sgT2C3lyXTMj9n6P9iUgfvSiKr8WNkiw7Wc+JvTbpVPCXsvsn7aHz01ERTIm/EdeoVptdDwQ==",
		"x",
	},
	{
		"BqiCJ0pVc3+T7Se93cAOco6ZRfemC1y5KpA6JTq/NLP4fgcmp0qdxzKtm56dGthKNlAnO5d0/hSuUfGGWsfMilnD09JbIsT6poqnDvTSQVPWrcHXLHZRvkccUGihYo6+HWMNct1XowHGdGRHeviPqOlqOtY6/3VrdtyOqfXP8EUwxyZ5c9myogjE10NInt/Wse8EbGnraOqQ4Taqcl5Sy32XfrXSeQYTomOH0JMOy+dkux0uHBoAFOxJDq5QAB7ErEwtEx+ivZ/Cy4sq77rvRSmqddDtetcwJxyKX8LOkV8nrKQkNgcHV3mn3gl4AsAuBua/vBm3SsMjfdK2cn7Ozg==",
		"testing.",
	},
	{
		"a8/xbBMdZ60nWxfHv84SNNw9Lleh4/rwaJcGegqX+Xb29OLSDKW4IKif7qtETS9JRzjnWi5id83pfhcK8lL5osxu1I9v4DxsVKbiIkkhVXvn8Q1KlFCUDL/j8vi9Y7xb0D7I1skAEmvoG0fPoL4S3arsodZY036kO0wUYx82+v/Za62G0NScHvSmGOHsysoPn5S2OfMjJ5b99M3bEXvLuKx/7HQE9OykT1sjeNoc7nk1p8G28UQtMTJrQMbPz0RocqgzVHLrlcZwLXKa5MNA+cLHCYdZ4ex4dBUbWEVpifBEW8uR9iA0qC7M/E1u8ehn1DguP13zRo/E4Hq6qbjUFg==",
		"testing.\n",
	},
	{
		"aWqtzeIT9ouu6zmY6hXPoNCljM6dvMn08bdUS3t1HZv+cx4RFpPvcHPzJnUyJ5YlMmPqQJtjUXLndJWiPTxqi/Z6EenH77psoYy1iI4DDwZsCmShWWIJETp1hd8LKDD1COqASjRBxLrxixIPcbMmtlSh9Go5SQRyPoQJSmxbbF4APUg82bCsLlZ+8zCIU5nOtUI6TMF3SMgfzB+l9aKWF//KX9pfPwDMxhXNWKYslT67T9Vr8duBYOdO8uEmHV4wnqUsqbDJ2uDUZhgQFfSLH9T7m49PQm3j1qfajmSoJ3JURuaWJmpztzjtmjblRVY3RE4UibQH765tu4owdSEPhQ==",
		"01234567890123456789012345678901234567890123456789012",
	},
}

// These test vectors were generated with `openssl rsautl -pkcs -encrypt`
var boringDecryptPKCS1v15SessionKeyTests = []DecryptPKCS1v15Test{
	{
		"HNUqIDhVgDveZxMdiFO/QyHEv5cYvd4hCtX7fkAUquyg9lKZh/jpZGWNwrZc72n/2+wQMx587ZCOKX8ZdUMV2NXMHLXf21UoiYOM2b3Cor+LodFudniyvaL2WbUbB9Z3P5NedPEmX8/yQ9UrkImWz6q1KUl4ZRGa4O6WPwDx5irvbiUuSb8DFd1kji5/VHdhd3+/t7Djmt7j9Xwoi06aKXLNq0LuJhxXpkkP7CyAH5Esdu2ys+zuIJwUJ2mYP2mYH90IyoyrbkGQFIeNYrEGEP9YiQ9JyvRO+FiwXk9LgLF83aq4oH0P3b+NPHwtigMK4NUTQMrZWZ/BtwHuCJVxHw==",
		"1234",
	},
	{
		"l7gEEnk+Zl2NtSUU+QWZqn/recoid9w4vkbT71uS+/RdJohVQywVSVrlyw+zAoHB7Wp93+mM1cyrtun8m8erQ+LoB4XMHkvucAJhudxubJMHKEgL85f0gIjqY+bf2rIGI1sEBOhNbay7d41Crzq+XUUk7sGWOnr0IDc42cGs+pY8VxTf8UzPH1oWogQa2q3iPVYrOB9EM9e49sDLEaIi9VfM6OZ3NmvKnqe9wAOKNoNRM7a1nt7NPlR2YuWWWB9WAKjbBQXi3fw7eW3x7ZMw0vWG01UYvG1Vzd8/Ftol4+8Kh8B9zt++xqZ9V+MlWX0iwn8YXPEJkVfItptirWkBmg==",
		"FAIL",
	},
	{
		"cg/Hpk8OntdKN7RGhp7rIrtKXzijkZnivlqMUzhe11peDKYkpOd1y2u+/pUS/7fJtuaUwM946h8r53X5ySc77kKOc1FOXlgTVX5p7PFNF6QfmRsJ0VP3CSCHO9FzwvnvW2DKOua87pFU2yPhkR/g+QIbyKu3sRBsc1LBCQ3YNfjOTBnXGMNH1Mtk6j62HKgdADB7yYK3NwQc6W0GbKMKZViHeScZ61OnLGPf7uDayLqeb6YajwNlxYsIjHgrj8tFCB5YyZErHYBHqEjgijDhsKQKUReVc7P9z4TWQojAm6HotReRkAwJjE9w2MK9TjeU8QEx1DfrKN5IjtFLlgk44Q==",
		"abcd",
	},
	{
		"LoI3iV8PU+Ebs2BEhuYJJXXZyuOUAAg9Qr6PgF3hUhQIgs3Fh6noDIVTiGsAA4PIW8rxr8CHaBAddCqFe0ZinIZFz7csS8xRuWjVshKDNuFTEZr0MYcprLWoaMsRYNvgNRhMO4iNz1LehRDvcH8+J+aZ4RpTyPzl/tEYjwj4NCeOQbONtdfcWsy6FiNihC0V2XEP6P+yDXf0H3T8YKYrtrKCa+sdGCIdaZ1wVc82VXEqlB9PwoiqaM/KDdp1vz2w7EcrStsvY7jJthR7h0jLU1nLVj5JLBnFgSNg8mn0IvcjWUYhpzGEaQJxOMCjvCWhozUKoe/+W++yCHcCeZyJAg==",
		"FAIL",
	},
}

// These vectors have been tested with
//   `openssl rsautl -verify -inkey pk -in signature | hexdump -C`
var boringSignPKCS1v15Tests = []signPKCS1v15Test{
	{"Test.\n", "1041d7cfaa132cf3bb77c59372fd6ce3fa7212ee7081f6cfa4aca3bb33b57d3aefe49d8e87513222e8d868921872a938c36d07e8a19a2ad487ba42af7ccb175eaa9d099caf17ec60190917890eb6a2f50287b15020bdebd784fb2e1685e1a74374845ac393e57c55548bfad0b3f4eafd09fa41d86f32dc8dd3f2acb6af7dbb462ad6549fd407bd94fe1ac521a65714a269625db73b223d4014ad6c2fe643e3099a1d75d58ea1a71c9a34713fb6a2b4c4e3b1e690f3b7c5f5b7595c541b1a4b3a659f6119b3fb2d355ae9866e03b1dfc87ec56c01bab47922745931535ace16193b4035a7d05ea58e85aaa757bbe698bc59e1e3985963062359cb6e924df05908"},
}

// In order to generate new test vectors you'll need the PEM form of this 2048-bit key (and s/TESTING/PRIVATE/):
// -----BEGIN RSA TESTING KEY-----
// MIIEowIBAAKCAQEA0pPiiTy/pnYkXmKR6+9ufL+5geYntx0iJNjV+x2s1lO13w2N
// f10NaSXbs0SOdzzAeB61WwYdTirSFGMTMLi5hY7O1AABN1BMalGZ4Dye80d+mL0R
// k4v6Wy1Alca0xVA5aTzg3Hd8FR1+hIEXm2wZCBU5mEyMBalKwOzlDq3BcQJrFoxB
// w15xn6Lci2hVF02c2pFJlzt9nrWBXrqbWlgLG04HzVWSyHepxXet34jTce2+6vpN
// /F7nxZ4fqy3Temx4LEi4IRvcKcrv/KzPhyIgiLG0FnNc7VB9PvG6RWmfjnWjVuEC
// wYQxhL6O106tYMkUtatJeQOZ5yv6yVJSSxkfvQIDAQABAoIBAEinpb3cK/PvR1UZ
// hWd2URTRwdvD4WgYsTMtbYcbEgtRDqtLLcsH/ByPZ2JPASi62V2YmtIxJeNWeu11
// 0aU51yjxwQL8jW7cUcFNLl5kDCO8Qz3H3kyeO19CGcqTqMN7jpN04dCvmSxf5Msr
// D04c2fYj/J9Dqfw6EQTHt7B82wV2Q9sSTSOmj0luNupJk1bgAc6ZhYaK5YbW2CFR
// kM7TzxMOA8nZDDKpd8qzu1QIlVZHstlBH8zr70216hBdBNn4Di02UiuIqDOlI2Qd
// udKqdRgMhHBEy7uHzS3p3rCy2Kvgj5qhF4JfWlwOE+IPx8g9SzHE0REpOj8jWrcS
// IMSRb4ECgYEA7wna3JN29fHoWs2l5MvP2mpKeZf4g3wHBOeHxtXHEFcNQolotFIV
// vbj+tj0Bs2trNQwmO0MUbCUzU276Aoke57jGxcDJgWSRjUtSA+hEB5gB2lL/E1lN
// nIX49UlDxiBHmelTD3QGAFRvRsC0EwgIYvJ0RR6Q5SMIANNDePZjAsUCgYEA4YUJ
// szE4jnjojvWAKtJQa7t1XWDY9mcDdC0uuvjl9ZJV+jSzJuCmL2L5PRsUT3PRXj/g
// Pjhdl0cOAo1dX+vEksqtSsxXYl/+14+aq+qJanipXohAewbFPGgaLvg8Ytd0gdoN
// FqGxIVhtiHuj3ZiAtk0+3VcGkhK9BWQXug2iGJkCgYBgG8hBk5DrBh50E+c1fLTP
// jpjvFqk2xHFWCXlP+rgU28tbC0Br7+0J4Q2YXCMI7pGmPIJKpYfai4J9c0tWJael
// Z2eULxVVzweulbAeHg7sNrPYAjLIpslLu5oDlTeIu4XOXj+lIPMgwtIS0nwUgtBM
// aEtTVxzO5CzdmBOy2O2qOQKBgQCyPSiWdL+DczIy0vvSXFjtXMJ84+92h6JmLtOx
// OMjfVyIW15IElycharMcRYu+5AXE3O1Jn9jwmFsNT1dOWZQKhJ+D747dFIvhKQGR
// AJRND0KlkUCNO6Olg422M8HeSPUvL/yKN488kJw5c6bmnAKWkuStoXty9dZpLVvH
// U8EaeQKBgA29EVw2VvjMxv5+H0uAiStK5oHzfn8L5OEgtbzGfzoJ6gahVKnxspM/
// u/8aviK8PaP14Sn2idMVo3MjR8YLdhxL7HsAZEWN67ZKKikjfFaHQTDp12Tw3XGX
// ZN8Zb7KNitpUY9Er8fwZf0uo6eFFahyC879D6Ji5Zxc67PK2uH2j
// -----END RSA TESTING KEY-----

var boringRSAPrivateKey = &PrivateKey{
	PublicKey: PublicKey{
		N: fromBase10("26582968808247670941880827147634583398709940903148296179974201159597151611191522474283740663896842298070274023752195115143062181798399931633038484825978864710556311526537036389359615134708657549470949679779904488622251108380449035061516780217275253588573014439875027815844411780800483641469602882283010827734994568193587133776489942056283110261563328687964858070367411163578609767826460417779122747360399007516530345955078459913485187921710920394993687650605870173080876599686371267593106814844268987944069622611828574462393861568531225119272056012941934088372978160492222275198856728666607081234560884010106521984957"),
		E: 65537,
	},
	D: fromBase10("9171827985597392851943318483639977414462504901078616250691619033840590692772978717190349632910194211574607263455523382877075881636715431803199203791522866302014118989853906447292363358500269534898410274488963490802544243140496415472344132845156599083644551970863086942824264754069617713671829048845437551867438555356824467579357412668715325116577461422154719187328073290313933069854469674883998702490224174554452359120544615831167852748978016281137536189669945536123236942252767400268719317140477252165488513392134354644004976837292665236471472063092377430761183380578589034563674767112048099575830012903689181818753"),
	Primes: []*big.Int{
		fromBase10("167858540191997219389724790985682836053090841001223010950246960935890691729682251780362544025461831459487863590214076790435803024090620129061663980947723946660281044270525458063401457629661038894952448290484953624899963083064364124050736445161263676729820811519036900008589825228516427511517446170713327338181"),
		fromBase10("158365304367844334017484465474489951375393993091627657156420383993142231985139253789640135888368021281916696955208780446273886683850078568739793470542666808372276986318923064464648843530039681086547711107991896076121433998218966001296374202537209431641579637449260487599626835676623454806487115724185432889497"),
	},
}
