package aba

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	br "github.com/GarryFCR/ADKG/broadcast"
	"github.com/coinbase/kryptology/pkg/core/curves"
	feld "github.com/coinbase/kryptology/pkg/sharing"
	rs "github.com/vivint/infectious"
)

func Coin(
	k, id int, //t+1,id
	coin_id string,
	curve *curves.Curve,
	shares []*feld.ShamirShare,
	T_j []int,
	commitment map[int][]curves.Point,
	chans []chan br.Message) bool {

	//Using secp256k curve
	g_tilde := curve.Point.Hash([]byte(coin_id))
	//Party's share of the secret
	u_ji := curve.Scalar.Zero()

	for _, i := range T_j {
		share_scalar, _ := curve.Scalar.SetBytes(shares[i].Value)
		u_ji = u_ji.Add(share_scalar)
	}

	//Generate proof
	proof := generate_proof(id, curve, g_tilde, u_ji)

	//Broadcast shares
	//msg = (z,h,h_tilde , g_i_tilde)
	g_i_tilde := g_tilde.Mul(u_ji)
	msg := make([]byte, 0)
	msg = append(msg, proof[:]...)
	msg = append(msg, g_i_tilde.ToAffineCompressed()...)
	br.Broadcast(chans, br.Message{Sender: id, Msgtype: "COIN", Value: rs.Share{}, Hash: nil, Output: msg})

	//wait for t+1 shares
	var done bool
	coin_shares := make(map[int]curves.Point, 0)
	for {
		done = false
		select {
		case x, ok := <-chans[id]:
			if ok {
				if x.Msgtype == "COIN" {
					z_, h_, h_tilde_, g_i_tilde_ := unpack(curve, x.Output)
					//Generate the pubkey of the node that send the share using the previous commitment
					g_i_ := Get_pubkey(k, x.Sender, curve, T_j, commitment)

					if verify(z_, h_, h_tilde_, g_tilde, g_i_, g_i_tilde_, curve) {
						coin_shares[x.Sender] = g_i_tilde_
					}
				} else {
					continue
				}
			}
		default:
			done = true
		}
		if done && len(coin_shares) >= k {
			break
		}
	}

	//Get the coin
	identities := make([]int, 0)

	for i := range coin_shares {
		identities = append(identities, i+1)
	}

	coeff, _ := LagrangeCoeffs(identities[0:k], curve)

	g_0_tilde := curve.Point.Identity()

	for i := range coeff {
		g_0_tilde = g_0_tilde.Add(coin_shares[i-1].Mul(coeff[i]))

	}

	if int(sha256.Sum256(g_0_tilde.ToAffineCompressed())[31])%2 == 1 {
		return true
	}
	return false
}

func unpack(
	curve *curves.Curve,
	msg []byte) (curves.Scalar, curves.Point, curves.Point, curves.Point) {

	z, _ := curve.Scalar.SetBytes(msg[0:32])
	h, _ := curve.Point.FromAffineCompressed(msg[32:65])
	h_tilde, _ := curve.Point.FromAffineCompressed(msg[65:98])
	g_i_tilde, _ := curve.Point.FromAffineCompressed(msg[98:131])

	return z, h, h_tilde, g_i_tilde
}

func Get_pubkey(
	k, id int, //t+1,id
	curve *curves.Curve,
	T_j []int,
	commitment map[int][]curves.Point) curves.Point {

	//g_i =  g^(u_ji)
	x := curve.Scalar.New(id + 1)
	var g_i curves.Point

	for l1, l2 := range T_j {
		i := curve.Scalar.One()
		rhs := commitment[l2][0]

		for j := 1; j < k; j++ {
			i = i.Mul(x)
			rhs = rhs.Add(commitment[l2][j].Mul(i))
		}

		if l1 == 0 {
			g_i = rhs
		} else {
			g_i = g_i.Add(rhs)
		}
	}
	return g_i
}

func generate_proof(id int,
	curve *curves.Curve,
	g_tilde curves.Point,
	x_i curves.Scalar) []byte {

	s := curve.NewScalar().Random(rand.Reader)
	g := curve.Point.Generator()
	h := g.Mul(s)
	h_tilde := g_tilde.Mul(s)

	g_i := g.Mul(x_i)
	g_i_tilde := g_tilde.Mul(x_i)

	c := Hash(g, h, g_tilde, h_tilde, g_i, g_i_tilde, curve)

	//z = s + xi * c
	z := x_i.MulAdd(c, s)

	proof := make([]byte, 0)
	proof = append(proof, z.Bytes()...)                    // s is 32 bytes
	proof = append(proof, h.ToAffineCompressed()...)       // 33 bytes
	proof = append(proof, h_tilde.ToAffineCompressed()...) // 33 bytes

	// z,h,h_tilde
	return proof

}

func verify(
	z curves.Scalar,
	h, h_tilde, g_tilde, g_i, g_i_tilde curves.Point,
	curve *curves.Curve) bool {

	g := curve.Point.Generator()
	c_ := Hash(g, h, g_tilde, h_tilde, g_i, g_i_tilde, curve)

	h_ := g.Mul(z).Sub(g_i.Mul(c_))

	h_tilde_ := g_tilde.Mul(z).Sub(g_i_tilde.Mul(c_))

	if h.Equal(h_) && h_tilde.Equal(h_tilde_) {
		return true
	}
	return false
}

func Hash(
	g, h, g_tilde, h_tilde, g_i, g_i_tilde curves.Point,
	curve *curves.Curve) curves.Scalar {

	//c = H(g, g i , h, g̃, g̃ i , h̃)
	plaintext := make([]byte, 0)
	plaintext = append(plaintext, g.ToAffineCompressed()...)
	plaintext = append(plaintext, g_i.ToAffineCompressed()...)
	plaintext = append(plaintext, h.ToAffineCompressed()...)
	plaintext = append(plaintext, g_tilde.ToAffineCompressed()...)
	plaintext = append(plaintext, g_i_tilde.ToAffineCompressed()...)
	plaintext = append(plaintext, h_tilde.ToAffineCompressed()...)

	sum := sha256.Sum256(plaintext)
	c := curve.Scalar.Hash(sum[:])

	return c
}

func LagrangeCoeffs(
	identities []int,
	curve *curves.Curve) (map[int]curves.Scalar, error) {

	xs := make(map[int]curves.Scalar, len(identities))
	for _, xi := range identities {
		xs[xi] = curve.Scalar.New(xi)
	}

	result := make(map[int]curves.Scalar, len(identities))
	for i, xi := range xs {
		num := curve.Scalar.One()
		den := curve.Scalar.One()
		for j, xj := range xs {
			if i == j {
				continue
			}

			num = num.Mul(xj)
			den = den.Mul(xj.Sub(xi))
		}
		if den.IsZero() {
			return nil, fmt.Errorf("divide by zero")
		}
		result[i] = num.Div(den)
	}
	return result, nil
}
