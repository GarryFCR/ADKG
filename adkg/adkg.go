package adkg

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"

	"errors"

	"github.com/GarryFCR/ADKG/aba"
	br "github.com/GarryFCR/ADKG/broadcast"
	"github.com/coinbase/kryptology/pkg/core/curves"
	feld "github.com/coinbase/kryptology/pkg/sharing"
	rs "github.com/vivint/infectious"

	acss "github.com/GarryFCR/ADKG/secret_sharing"
)

func hasBit(n int, pos uint) bool {
	val := n & (1 << pos)
	return (val > 0)
}
func setBit(n int, pos uint) int {
	n |= (1 << pos)
	return n
}

func countSetBits(n int) int {
	count := 0
	for n > 0 {
		n &= (n - 1)
		count++
	}
	return count
}

func predicate(
	sk []byte,
	T_j []byte,
	k, id int,
	curve *curves.Curve,
	chans []chan br.Message) bool {

	buffer := make([]br.Message, 0)

	done := false
	for {
		select {
		case x, ok := <-chans[id]:
			if ok {
				if x.Msgtype == "T_i" {
					a := binary.BigEndian.Uint64(x.Output)
					b := binary.BigEndian.Uint64(T_j)
					if b&a == b { // Checking if T_j is a subset of T_i
						done = true
					} else {
						return false
					}
				} else {
					buffer = append(buffer, x)
				}
			}
		default:
			time.Sleep(100 * time.Millisecond)
		}
		if done {
			break

		}
	}
	if len(buffer) > 0 {
		for _, i := range buffer {

			chans[id] <- i
		}
	}

	return true

}

func read(chans chan br.Message, str string) ([]byte, error) {

	done := false
	for {
		select {
		case x, ok := <-chans:
			if ok {
				if x.Msgtype == str {
					return x.Output, nil
				}

			}

		default:
			done = true
		}
		if done {
			break
		}

	}
	return []byte{0}, errors.New("NO OUTPUT")
}

func Adkg(
	n, k, id, sid uint32,
	secret curves.Scalar,
	curve *curves.Curve,
	chans [][]chan br.Message) ([]int, []*feld.ShamirShare, map[int][]curves.Point) {

	//call sharing
	fmt.Println("SHARING PHASE OF ADKG STARTED(NODE -", id, "):")
	acss.Acss(secret, n, k, id, sid, curve, chans[sid])
	fmt.Println()
	time.Sleep(3 * time.Second)

	//Key set proposal
	fmt.Println("KEY SET PROPOSAL PHASE OF ADKG STARTED(NODE -", id, "):")
	S_i := make([]*feld.ShamirShare, n)
	C_i := make(map[int][]curves.Point)
	T_i_set := make([]int, 0)
	T_i := 0
	sk_i := br.Getprivk(curve, int(id))
	done := false
	for i := 0; i < int(n); i++ {
		for {
			select {
			case x, ok := <-chans[i][id]:
				if ok {
					if x.Msgtype == "OUTPUT" && !hasBit(T_i, uint(x.Sid)) {
						pk_d, _ := curve.Point.FromAffineCompressed(x.Output[(k*33)+(n*52) : (k*33)+(n*52)+33])
						K_i := pk_d.Mul(sk_i)
						pos := ((k * 33) + (id * 52))
						key := sha256.Sum256(K_i.ToAffineCompressed())
						plaintext := acss.DecryptAES(key[:], x.Output[pos:pos+52])

						ss := acss.Byte_2_shamirshare(plaintext)
						verifier, _ := acss.Get_verifier(int(k), x.Output, curve)
						if verifier.Verify(ss) == nil {
							S_i[x.Sid] = ss //collect shares
							T_i = setBit(T_i, uint(x.Sid))
							T_i_set = append(T_i_set, x.Sid)
							C_i[i] = verifier.Commitments //collect commitments
						}

					}
				}
			default:
				done = true
			}
			if done || countSetBits(T_i) >= int(k) {
				break
			}

		}
	}
	if countSetBits(T_i) >= int(k) {

		var output [8]byte
		binary.BigEndian.PutUint64(output[:], uint64(T_i))
		for i := 0; i < int(n); i++ {
			chans[i][id] <- br.Message{
				Sender:  int(id),
				Sid:     int(sid),
				Msgtype: "T_i",
				Value:   rs.Share{},
				Hash:    nil,
				Output:  output[:]}

		}
		time.Sleep(100 * time.Millisecond)

		br.Rbc(chans[sid], output[:], int(n), int(k-1), int(id), int(sid), curve, curve.NewIdentityPoint(), predicate, "KEY SET PROPOSAL")

	}
	fmt.Println()
	time.Sleep(3 * time.Second)

	//Agreement phase
	fmt.Println("AGREEMENT PHASE OF ADKG STARTED(NODE -", id, "):")

	var wg sync.WaitGroup
	aba_check := make([]bool, n)
	decision := make([]int, n)
	T := make([]int, 0)
	for i := 0; i < 2; i++ { //reading only for two acss here just to test,since reading all n takes longer

		share_byte, err := read(chans[i][id], "OUTPUT_SET")
		if err != nil {
			panic(err)
		}

		a := binary.BigEndian.Uint64(share_byte) //T_j
		b := uint64(T_i)
		if b&a == a { // Checking if T_j is a subset of T_i
			//Input 1 into jth ABA
			wg.Add(1)

			go func(index int) {
				aba_check[index] = true
				defer wg.Done()
				decision_i, err := aba.Propose(1, int(id), int(n), int(k), chans[index], curve, index, S_i, T_i_set, C_i)

				if err == nil {
					decision[index] = decision_i
				} else {
					panic(err)
				}

			}(i)
			done = true

		}
		wg.Wait()

	}

	fmt.Println("Node- ", id, "'s decision ABA output :", decision)
	fmt.Println()
	for j1, j2 := range decision {
		if j2 == 1 {
			T = append(T, j1)
		}
	}
	var wg1 sync.WaitGroup

	for j1, j2 := range aba_check {
		if j2 == false {
			go func() {
				wg1.Add(1)
				aba.Propose(0, int(id), int(n), int(k), chans[j1], curve, j1, S_i, T_i_set, C_i)
				wg1.Done()
			}()
		}
	}
	wg1.Wait()
	time.Sleep(time.Second)

	return T, S_i, C_i

}

func keyDerive(
	id, k uint32,
	g, h curves.Point,
	curve *curves.Curve,
	T []int,
	S_i []*feld.ShamirShare,
	C_i map[int][]curves.Point,
	agree_Chans []chan br.Message) {

	//Key derivation phase
	Z_i := curve.Scalar.Zero()
	for _, j := range T {
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
	aba.Broadcast(agree_Chans, br.Message{
		Sender:  int(id),
		Sid:     int(id),
		Msgtype: "PUBKEY_SHARE",
		Value:   rs.Share{Number: 0, Data: h_zi.ToAffineCompressed()}, //pub key share,
		Hash:    C.Bytes(),
		Output:  S.Bytes()})
	time.Sleep(time.Second)

	H := make(map[int]curves.Point)
	done := false
	for {
		select {
		case x, ok := <-agree_Chans[id]:
			if ok {
				if x.Msgtype == "PUBKEY_SHARE" {
					g_zj := aba.Get_pubkey(int(k), x.Sender, curve, T, C_i)

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

	fmt.Println(id, "'s share of private key:", Z_i.BigInt(), "\nPublic key :", h_z.ToAffineCompressed())
	fmt.Println()
	agree_Chans[id] <- br.Message{
		Sender:  int(id),
		Sid:     0,
		Msgtype: "SHARE",
		Value:   rs.Share{},
		Hash:    h_z.ToAffineCompressed(),
		Output:  Z_i.Bytes()}

	return

}

func RunAdkg(n, k, id, sid uint32,
	g, h curves.Point,
	curve *curves.Curve,
	chans [][]chan br.Message,
	output_chans []chan br.Message) ([]int, map[int][]curves.Point) {

	s, _ := rand.Int(rand.Reader, big.NewInt(int64(math.Pow(2, float64(32)))))
	secret := curve.Scalar.New(int(s.Int64()))

	T, S_i, C_i := Adkg(n, k, id, sid, secret, curve, chans)
	fmt.Println("KEY DERIVATION PHASE OF ADKG STARTED(NODE -", id, "):")

	keyDerive(id, k, g, h, curve, T, S_i, C_i, output_chans)
	return T, C_i
}
