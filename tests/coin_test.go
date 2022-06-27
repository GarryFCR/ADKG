package tests

import (
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
	priv, pub := acss.Generate(7)
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
		c[i], _ = acss.Acss(secret, 7, 3, uint32(i), chans[:], priv, pub)
		//collect
		verifier, _ := acss.Get_verifier(3, c[i])
		commitment[i] = verifier.Commitments
	}

	//collect shares
	for i1 := range c {
		for i2, key := range priv {
			pos := ((3 * 33) + (i2 * 150))
			plaintext, _ := key.Decrypt(c[i1][pos : pos+150])
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
