package main

import (
	"crypto/rand"
	"fmt"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// AcssNIZK prove: g^sk_i = pk_i && pk_d^sk_i = K_i
func AcssNIZK(g, pk_i, pk_d, K_i curves.Point, sk_i curves.Scalar) { // maybe enforce specific curve points K256Point and scalar K256Scalar
	Commit := func(g, h curves.Point) ([]curves.Point, curves.Scalar) {
		k := curves.K256().NewScalar().Random(rand.Reader)
		return []curves.Point{g.Mul(k), h.Mul(k)}, k
	}
	Challenge := func(public_inputs, r []curves.Point) curves.Scalar {
		bs := []byte{}
		for _, P := range append(public_inputs, r...) {
			bs = append(bs, P.ToAffineCompressed()...)
		}
		return curves.K256().NewScalar().Hash(bs) // is this a cryptographic hash cipher with output the size of our field?
	}
	Response := func(x, k, e curves.Scalar) curves.Scalar {
		return k.Sub(e.Mul(x))
	}
	// Chaum-Pedersen: prove: g^x = y1 && h^x = y2
	g, h, y1, y2, x := g, pk_d, pk_i, K_i, sk_i
	public_inputs := []curves.Point{g, h, y1, y2}
	for _, P := range public_inputs { // check everything in curve.
		if !P.IsOnCurve() { // are we checking it's a K256 curve or just generic?
			panic(fmt.Sprintf("PROOF INPUT(s) INVALID: %v is not on the Curve!", P.ToAffineCompressed()))
		}
	}

	r, k := Commit(g, h)
	e := Challenge(public_inputs, r)
	s := Response(x, k, e)
	if !(r[0].Equal(g.Mul(s).Add(y1.Mul(e))) && r[1].Equal(h.Mul(s).Add(y2.Mul(e)))) {
		panic(fmt.Sprintf("PROOF INVALID (r1 r2) = (%v %v) e = %s s = %s", r[0].ToAffineCompressed(), r[1].ToAffineCompressed(), e.BigInt(), s.BigInt()))
	}
	fmt.Printf("Proof is: \n\tr = %v %v\n\te = %s (*optional)\n\ts = %s\n", r[0].ToAffineCompressed(), r[1].ToAffineCompressed(), e.BigInt(), s.BigInt())
}

func main() {
	g := curves.K256().NewGeneratorPoint()
	sk_i := curves.K256().NewScalar().Random(rand.Reader)
	pk_i := g.Mul(sk_i)
	sk_d := curves.K256().NewScalar().Random(rand.Reader)
	pk_d := g.Mul(sk_d)
	K_i := pk_i.Mul(sk_d)
	AcssNIZK(g, pk_i, pk_d, K_i, sk_i)
	println("DONE :)")
}
