package main

import (
	br "github.com/GarryFCR/ADKG/broadcast"
	feld "github.com/GarryFCR/ADKG/secret_sharing"
)

func main() {

	//Represent the nodes
	var chans [7]chan br.Message
	for i := range chans {
		chans[i] = make(chan br.Message, 100)
	}
	feld.Acss(100, 7, 3, 0, chans[:])
}
