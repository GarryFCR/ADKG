package main

import (
	"fmt"

	br "github.com/GarryFCR/ADKG/broadcast"
	feld "github.com/GarryFCR/ADKG/secret_sharing"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

func main() {

	//Represent the nodes
	var chans [7]chan br.Message
	priv, pub := feld.Generate(7)
	for i := range chans {
		chans[i] = make(chan br.Message, 100)
	}
	c, check := feld.Acss(100, 7, 3, 0, chans[:], priv, pub)
	if check {
		result, err := feld.Acss_reconstruct(c, 7, 3, 3, chans[:], priv)
		y := curves.K256().NewScalar().New(100) // 100 in scalar form
		if result.Cmp(y) == 0 && err == nil {
			fmt.Println("Correct Reconstruction")
		}
	}
}
