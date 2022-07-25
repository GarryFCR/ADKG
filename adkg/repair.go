package adkg

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"time"

	"github.com/GarryFCR/ADKG/aba"
	acss "github.com/GarryFCR/ADKG/secret_sharing"
	feld "github.com/coinbase/kryptology/pkg/sharing"
	rs "github.com/vivint/infectious"

	br "github.com/GarryFCR/ADKG/broadcast"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

func lagrangeCoeffsAtX(
	id, index int,
	identities []int,
	curve *curves.Curve) (curves.Scalar, error) {

	x := curve.NewScalar().New(index + 1)
	xi := curve.NewScalar().New(id + 1)

	xs := make(map[int]curves.Scalar, len(identities))
	for _, i := range identities {
		xs[i] = curve.Scalar.New(i)
	}
	num := curve.Scalar.One()
	den := curve.Scalar.One()
	for _, xj := range xs {
		if xi.Cmp(xj) == 0 {
			continue
		}

		num = num.Mul(x.Sub(xj))
		den = den.Mul(xi.Sub(xj))
	}
	if den.IsZero() {

		return nil, fmt.Errorf("divide by zero")
	}
	result := num.Div(den)
	return result, nil
}

//For nodes except lost index node
func Enrollment(
	id, lost_index, n, k, sid int,
	identities []int, //Group of nodes that will perform the enrollment
	curve *curves.Curve,
	chans [][]chan br.Message,
	out_chan []chan br.Message) {

	//Step 1
	Y, err := lagrangeCoeffsAtX(id, lost_index, identities, curve)
	if err != nil {
		panic(err)
	}

	//Step 2
	done := false
	share := curve.Scalar.Zero()
	for {
		select {
		case x, ok := <-out_chan[id]:
			if ok {
				if x.Msgtype == "SHARE" {
					share, err = curve.Scalar.SetBytes(x.Output)
					if err != nil {
						panic(err)
					}
					out_chan[id] <- x
					done = true
				}
			}

		default:
			done = true
		}
		if done {
			break
		}

	}
	QxY := share.Mul(Y)
	acss.Acss(QxY, uint32(n), uint32(k), uint32(id), uint32(sid), curve, chans[sid])
	time.Sleep(time.Second * 2)

	//Step 3
	C := make([]curves.Point, k)
	for j := 0; j < k; j++ {
		C[j] = curve.Point.Identity()
	}
	sk_i := br.Getprivk(curve, int(id))
	S := curve.Scalar.Zero().Bytes()
	count := 0
	done = false
	for i := 0; i < int(n); i++ {
		for {
			select {
			case x, ok := <-chans[i][id]:
				if ok {
					if x.Msgtype == "OUTPUT" {
						pk_d, _ := curve.Point.FromAffineCompressed(x.Output[(k*33)+(n*52) : (k*33)+(n*52)+33])
						K_i := pk_d.Mul(sk_i)
						pos := ((k * 33) + (id * 52))
						key := sha256.Sum256(K_i.ToAffineCompressed())
						plaintext := acss.DecryptAES(key[:], x.Output[pos:pos+52])

						ss := acss.Byte_2_shamirshare(plaintext)
						s1, _ := curve.Scalar.SetBytes(ss.Value)
						s2, _ := curve.Scalar.SetBytes(S)
						S = s1.Add(s2).Bytes()
						verifier, _ := acss.Get_verifier(int(k), x.Output, curve)
						for j := 0; j < k; j++ {
							C[j] = C[j].Add(verifier.Commitments[j])
						}
						count++
					}
				}
			default:
				done = true
			}
			if done {
				break
			}

		}
	}
	if count < k {
		panic("Not enough shares to repair")
	}

	verifier := new(feld.FeldmanVerifier)
	verifier.Commitments = C
	Share := &feld.ShamirShare{Id: uint32(id + 1), Value: S}

	if verifier.Verify(Share) == nil {
		chans[identities[0]-1][lost_index] <- br.Message{
			Sender:  id,
			Sid:     sid,
			Msgtype: "REPAIR_SHARE",
			Value:   rs.Share{},
			Hash:    nil,
			Output:  Share.Bytes(),
		}
	}

}

func Repair(
	id, n, k, sid int,
	identities []int,
	curve *curves.Curve,
	chans [][]chan br.Message,
	out_chan []chan br.Message) *big.Int {

	//Step 4
	C := make([]curves.Point, k) //Commitments
	S_i := make(map[int]*feld.ShamirShare, n)
	S := curve.Scalar.Zero()

	coeff, err := aba.LagrangeCoeffs(identities, curve)
	if err != nil {
		panic(err)
	}
	for j := 0; j < k; j++ {
		C[j] = curve.Point.Identity()
	}
	done := false
	for _, i := range identities {
		for {
			select {
			case x, ok := <-chans[i-1][id]:
				if ok {
					if x.Msgtype == "OUTPUT" {
						verifier, _ := acss.Get_verifier(int(k), x.Output, curve)
						for j := 0; j < k; j++ {
							C[j] = C[j].Add(verifier.Commitments[j])
						}
					} else if x.Msgtype == "REPAIR_SHARE" {
						ss := acss.Byte_2_shamirshare(x.Output)
						S_i[x.Sender] = ss

					}
				}
			default:
				done = true
			}
			if done {
				break
			}

		}

	}
	verifier := new(feld.FeldmanVerifier)
	verifier.Commitments = C
	for _, s := range S_i {
		if verifier.Verify(s) != nil {
			panic("Incorrect share")
		}
		s1, err := curve.Scalar.SetBytes(s.Value)
		if err != nil {
			panic(err)
		}
		S = S.Add(s1.Mul(coeff[int(s.Id)]))
	}

	out_chan[id] <- br.Message{
		Sender:  int(id),
		Sid:     0,
		Msgtype: "SHARE",
		Value:   rs.Share{},
		Hash:    nil,
		Output:  S.Bytes()}

	return S.BigInt()
}

func VerifyRepairshare() {

}

func Disenrollment(
	id, n, k, sid uint32,
	g, h curves.Point,
	T []int,
	C_i map[int][]curves.Point,
	curve *curves.Curve,
	chans [][]chan br.Message,
	out_chan []chan br.Message) {

	zero := curve.Scalar.Zero()
	Adkg(n, k, id, sid, zero, curve, chans)
	/*
		//Getting original share
		done := false
		Z_i := curve.Scalar.Zero() //Share + shares from the zero polynomials
		for {
			select {
			case x, ok := <-out_chan[id]:
				if ok {
					if x.Msgtype == "SHARE" {
						Z_i, _ = curve.Scalar.SetBytes(x.Output)
						done = true
					}
				}

			default:
				done = true
			}
			if done {
				break
			}

		}

		//Key derivation phase
		for _, j := range T_zero {
			share_scalar, _ := curve.Scalar.SetBytes(S_i[j].Value)
			Z_i = Z_i.Add(share_scalar)
		}

		g_zi := g.Mul(Z_i)
		h_zi := h.Mul(Z_i)

		k_rand := curve.Scalar.Random(rand.Reader)
		A := g.Mul(k_rand)
		B := h.Mul(k_rand)

		//c=Hash(g,g_zi,h,h_zi,A,B)
		C := aba.Hash(g, g_zi, h, h_zi, A, B, curve)

		// S=k_rand − C*Z_i
		S := C.Mul(Z_i).Sub(k_rand)
		S = S.Neg()

			//Send (C,S)
			aba.Broadcast(out_chan, br.Message{
				Sender:  int(id),
				Sid:     int(id),
				Msgtype: "DISENROLL_PUBKEY_SHARE",
				Value:   rs.Share{Number: 0, Data: h_zi.ToAffineCompressed()}, //pub key share,
				Hash:    C.Bytes(),
				Output:  S.Bytes()})
			time.Sleep(time.Second)

			H := make(map[int]curves.Point)
			done = false
			for {
				select {
				case x, ok := <-out_chan[id]:
					if ok {
						if x.Msgtype == "DISENROLL_PUBKEY_SHARE" {
							g_zj_1 := aba.Get_pubkey(int(k), x.Sender, curve, T, C_i)
							g_zj_2 := aba.Get_pubkey(int(k), x.Sender, curve, T_zero, C_i_zero)
							g_zj := g_zj_1.Add(g_zj_2)

							S_, err1 := curve.Scalar.SetBytes(x.Output)
							C1, err2 := curve.Scalar.SetBytes(x.Hash)
							h_zj, err3 := curve.Point.FromAffineCompressed(x.Value.Data)

							if err1 != nil {
								panic(err1)
							}
							if err2 != nil {
								panic(err1)
							}
							if err3 != nil {
								panic(err1)
							}
							//A′=s*g + c*(g_zj)
							a1 := g.Mul(S_)
							a2 := g_zj.Mul(C1)
							A_ := a1.Add(a2)

							//B′=s*h +c*h_zj
							b1 := h.Mul(S_)
							b2 := h_zj.Mul(C1)
							B_ := b1.Add(b2)

							//c=Hash(g,g_zi,h,h_zi,A,B)
							C2 := aba.Hash(g, g_zj, h, h_zj, A_, B_, curve)
							if C1.Cmp(C2) == 0 {
								H[x.Sender] = h_zj
							}
						}
					}
				default:
					done = true
				}
				if done {
					break
				}

			}

			//Interpolate to get h_z
			h_z := curve.Point.Identity()

			if len(H) >= int(k) {
				identities := make([]int, 0)

				for i := range H {
					identities = append(identities, i+1)
				}

				coeff, _ := aba.LagrangeCoeffs(identities[0:k], curve)

				for i := range coeff {
					h_z = h_z.Add(H[i-1].Mul(coeff[i]))

				}
			}

			fmt.Println(id, Z_i.BigInt(), h_z.ToAffineCompressed())
			out_chan[id] <- br.Message{
				Sender:  int(id),
				Sid:     0,
				Msgtype: "SHARE",
				Value:   rs.Share{},
				Hash:    h_z.ToAffineCompressed(),
				Output:  Z_i.Bytes()}

			return
	*/
}
