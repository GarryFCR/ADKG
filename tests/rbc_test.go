package tests

import (
	"math/rand"
	"sync"
	"testing"
	"time"

	br "github.com/GarryFCR/ADKG/broadcast"
	acss "github.com/GarryFCR/ADKG/secret_sharing"

	"gitlab.com/elktree/ecc"
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
	sk, _ := acss.Generate(7)
	output := br.Rbc(sk, chans[:], msg, 7, 2, 0, predicate)
	for _, o := range output {
		if o != string(msg) {
			t.Fatalf("Incorrect value was recieved from the broadcast")
		}
	}

}

func predicate(
	sk *ecc.PrivateKey,
	c []byte,
	k, i int,
	chans []chan br.Message) bool {

	return true

}
