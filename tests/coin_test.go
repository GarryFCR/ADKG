package tests

import (
	"crypto/sha256"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/coinbase/kryptology/pkg/core/curves"

	coin "github.com/GarryFCR/ADKG/aba"
	br "github.com/GarryFCR/ADKG/broadcast"
	acss "github.com/GarryFCR/ADKG/secret_sharing"
	feld "github.com/coinbase/kryptology/pkg/sharing"
)

var wg1 sync.WaitGroup

func TestCoin(t *testing.T) {

	// Generate shares and commitment for 7 secrets of 7  nodes
	//Represent the nodes

	commitment := make(map[int][]curves.Point, 0)
	shares := make(map[int][]*feld.ShamirShare)

	source := rand.NewSource(time.Now().UnixNano())

	random := rand.New(source)
	c := make([][]byte, 7)
	for i := 0; i < 7; i++ {
		//communication channels
		var chans [7]chan br.Message
		for j := range chans {
			chans[j] = make(chan br.Message, 100)
		}

		//Run acss
		secret := random.Intn(1000)
		c[i], _ = acss.Acss(curves.K256().NewScalar().New(secret), 7, 3, uint32(i), uint32(i), curves.K256(), chans[:])
		//collect
		verifier, _ := acss.Get_verifier(3, c[i], curves.K256())
		commitment[i] = verifier.Commitments
	}

	//collect shares
	for i1 := range c {
		for i2 := 0; i2 < 7; i2++ {
			sk_i := br.Getprivk(curves.K256(), i2)
			pk_d, _ := curves.K256().Point.FromAffineCompressed(c[i1][(3*33)+(7*52) : (3*33)+(7*52)+33])
			K_i := pk_d.Mul(sk_i)

			pos := ((3 * 33) + (i2 * 52))
			key := sha256.Sum256(K_i.ToAffineCompressed())
			plaintext := acss.DecryptAES(key[:], c[i1][pos:pos+52])

			ss := acss.Byte_2_shamirshare(plaintext)
			shares[i2] = append(shares[i2], ss)
		}
	}

	var chans [7]chan br.Message
	for j := range chans {
		chans[j] = make(chan br.Message, 100)
	}
	curve := curves.K256()
	bits := new(int)

	T_j := []int{1, 3, 4}
	for i := 0; i < 7; i++ {
		wg1.Add(1)
		go coinflip(3, i, "testcoin", curve, shares[i], T_j, commitment, chans[:], bits)
	}
	wg1.Wait()
	if *bits != 7 && *bits != -7 {
		t.Fatalf("Common coin not recieved at all nodes")
	}
}

func coinflip(
	k, id int, //t+1,id
	coin_id string,
	curve *curves.Curve,
	shares []*feld.ShamirShare,
	T_j []int,
	commitment map[int][]curves.Point,
	chans []chan br.Message,
	bits *int) {

	bit := coin.Coin(3, id, "testcoin", curve, shares, T_j, commitment, chans[:])
	if bit {
		*bits += 1
	} else {
		*bits -= 1
	}
	wg1.Done()
}
