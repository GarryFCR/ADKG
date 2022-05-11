package main

import (
	br "github.com/GarryFCR/ADKG/broadcast"
	//rs "github.com/vivint/infectious"
)

func main() {

	//RBC--------------------------------------------------------------
	//Represent the nodes
	var chans [7]chan br.Message
	for i := range chans {
		chans[i] = make(chan br.Message, 15)
	}
	//Call rbc
	msg := []byte("hello, world!")
	br.Rbc(chans[:], msg)

}
