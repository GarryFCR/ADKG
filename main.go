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
	/*
		shares, f := encode(14, 8, []byte("hello, world!"))
		// we now have total shares.
		for _, share := range shares {
			fmt.Printf("%d: %#v\n", share.Number, string(share.Data))
		}

		// Let's reconstitute with two pieces missing and one piece corrupted.
		shares = shares[2:]     // drop the first two pieces
		shares[2].Data[1] = '!' // mutate some data
		shares[3].Number = 8

		for i, j := 0, len(shares)-1; i < j; i, j = i+1, j-1 {
			shares[i], shares[j] = shares[j], shares[i]
		}
		// we now have total shares.
		for _, share := range shares {
			fmt.Printf("%d: %#v\n", share.Number, string(share.Data))
		}

		y := decode(14, 7, shares, f)
		fmt.Println(string(y))
	*/
}

/*
func encode(n int, k int, msg []byte) ([]rs.Share, *rs.FEC) {

	f, err := rs.NewFEC(k, n)
	if err != nil {
		panic(err)
	}

	shares := make([]rs.Share, n)
	output := func(s rs.Share) {
		shares[s.Number] = s.DeepCopy()
	}

	//the data to encode must be padded to a multiple of required
	if len(msg)%8 != 0 {
		for len(msg)%8 != 0 {
			msg = append(msg, byte(0))
		}
	}

	err = f.Encode(msg, output)
	if err != nil {
		panic(err)
	}

	return shares, f
}

func decode(n int, k int, shares []rs.Share, f *rs.FEC) []byte {

	result, err := f.Decode(nil, shares)
	if err != nil {
		panic(err)
	}

	for {
		if result[len(result)-1] != 0 {
			return result
		}
		result = result[:(len(result) - 1)]
	}
}
*/
