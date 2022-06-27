package tests

import (
	"testing"

	br "github.com/GarryFCR/ADKG/broadcast"
	acss "github.com/GarryFCR/ADKG/secret_sharing"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestAcss(t *testing.T) {
	//Represent the nodes
	var chans [7]chan br.Message
	priv, pub := acss.Generate(7)
	for i := range chans {
		chans[i] = make(chan br.Message, 100)
	}
	c, check := acss.Acss(100, 7, 3, 0, chans[:], priv, pub)
	if check {
		result, err := acss.Acss_reconstruct(c, 7, 3, 3, chans[:], priv)
		y := curves.K256().NewScalar().New(100) // 100 in scalar form
		if result.Cmp(y) != 0 || err != nil {
			t.Fatalf("Reconstruction failed")
		}
	}
}
