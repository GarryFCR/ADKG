package tests

import (
	"math/rand"
	"sync"
	"testing"
	"time"

	br "github.com/GarryFCR/ADKG/broadcast"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

var wg sync.WaitGroup

func TestReedSolomon(t *testing.T) {

	msg1 := []byte("hello, world!")
	shares, fec, err := br.Rs_enc(14, 7, msg1)
	if err != nil {
		t.Fatalf("Encoding failed")
	}

	shares = shares[2:]
	_, err = br.Rs_dec(14, 7, shares, fec)
	if err != nil {
		t.Fatalf("Decoding failed when shares are lost within the allowable range")
	}

	shares[1].Data[0] = byte(0)
	_, err = br.Rs_dec(14, 7, shares, fec)
	if err != nil {
		t.Fatalf("Decoding failed when shares are corrupted")
	}

}

func TestRbc(t *testing.T) {

	var chans [7]chan br.Message
	for i := range chans {
		chans[i] = make(chan br.Message, 15)
	}

	source := rand.NewSource(time.Now().UnixNano())

	random := rand.New(source)
	letters := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	msg := make([]byte, 20)
	for i := range msg {
		msg[i] = letters[random.Intn(len(letters))]
	}

	//Call rbc
	output := br.Rbc(chans[:], msg, 7, 2, 0, 1, curves.K256(), curves.K256().NewIdentityPoint(), predicate, "")
	for _, o := range output {
		if o != string(msg) {
			t.Fatalf("Incorrect value was recieved from the broadcast")
		}
	}

}

func predicate(
	x []byte,
	c []byte,
	k, i int,
	curve *curves.Curve,
	chans []chan br.Message) bool {

	return true

}
