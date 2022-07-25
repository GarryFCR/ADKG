package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/GarryFCR/ADKG/adkg"
	br "github.com/GarryFCR/ADKG/broadcast"
	acss "github.com/GarryFCR/ADKG/secret_sharing"
	"github.com/coinbase/kryptology/pkg/core/curves"
	//"github.com/GarryFCR/ADKG/adkg"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}
func Gen_keypair(curve *curves.Curve, n int) {
	priv, pub := acss.Generate(curve, n)

	f, err := os.Create("./NodeKeys/Pubkey.txt")
	check(err)
	defer f.Close()
	for _, i := range pub {
		_, err := f.Write(i.ToAffineCompressed()) //33 bytes
		check(err)
	}

	for j, i := range priv {
		str1 := strconv.Itoa(j)
		str2 := "./NodeKeys/Privkey"
		filename := str2 + str1 + ".txt"
		f, err := os.Create(filename)
		check(err)
		defer f.Close()

		privkey := i.Bytes() // 32 bytes
		check(err)
		_, err = f.Write(privkey)
		check(err)
	}

}
func call_adkg(
	n, k int,
	curve *curves.Curve,
	out_chan []chan br.Message) ([]int, map[int][]curves.Point) {
	var wg sync.WaitGroup

	//A list of a list of channels - first index is sid second indicates the node
	//Each node will have multiple channels one for each session
	chan_list := make([][]chan br.Message, n)

	for i := 0; i < n; i++ {
		chan_session := make([]chan br.Message, n)
		for i := range chan_session {
			chan_session[i] = make(chan br.Message, 1000)
		}
		chan_list[i] = chan_session[:]

	}

	g := curve.Point.Generator()
	x := curve.Scalar.Random(rand.Reader)
	h := g.Mul(x)
	var C map[int][]curves.Point
	var T []int
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(index int) {
			T, C = adkg.RunAdkg(uint32(n), uint32(k), uint32(index), uint32(index), g, h, curve, chan_list[:], out_chan[:])
			defer wg.Done()
		}(i)

	}
	wg.Wait()
	return T, C
}

func call_repair(
	lost_index, n, k int,
	identities []int, //Group of nodes that will perform the enrollment
	curve *curves.Curve,
	out_chan []chan br.Message) {

	//Enrollment
	chan_list := make([][]chan br.Message, n)
	for i := 0; i < n; i++ {
		chan_session := make([]chan br.Message, n)
		for i := range chan_session {
			chan_session[i] = make(chan br.Message, 1000)
		}
		chan_list[i] = chan_session[:]
	}

	var wg sync.WaitGroup
	for _, i := range identities {

		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			adkg.Enrollment(index-1, lost_index, n, k, index-1, identities, curve, chan_list, out_chan)
		}(i)
	}

	wg.Wait()

	//repair
	share := adkg.Repair(lost_index, n, k, identities[0], identities, curve, chan_list, out_chan)

	fmt.Println()
	fmt.Println("REPAIRED SHARE OF NODE -", lost_index, " IS :", share)

}

/*
func call_disenroll(
	n, k uint32,
	T []int,
	C_i map[int][]curves.Point,
	curve *curves.Curve,
	out_chan []chan br.Message) {

	var wg sync.WaitGroup
	chan_list := make([][]chan br.Message, n)
	for i := 0; i < int(n); i++ {
		chan_session := make([]chan br.Message, n)
		for i := range chan_session {
			chan_session[i] = make(chan br.Message, 1000)
		}
		chan_list[i] = chan_session[:]

	}

	g := curve.Point.Generator()
	x := curve.Scalar.Random(rand.Reader)
	h := g.Mul(x)

	for i := 0; i < int(n); i++ {
		wg.Add(1)
		go func(index int) {
			adkg.Disenrollment(uint32(index), n, k, uint32(index), g, h, T, C_i, curve, chan_list, out_chan)
			defer wg.Done()
		}(i)

	}
	wg.Wait()

}*/
func main() {

	var out_chan [7]chan br.Message
	for i := range out_chan {
		out_chan[i] = make(chan br.Message, 100)
	}
	curve := curves.K256()

	Gen_keypair(curve, 7)
	call_adkg(7, 3, curve, out_chan[:])
	fmt.Println("REPAIRING NODE - 0's USING NODES - 2,3,4")

	call_repair(0, 7, 3, []int{2, 3, 4}, curve, out_chan[:])
	//call_disenroll(7, 3, T, C, curve, out_chan[:])

}
