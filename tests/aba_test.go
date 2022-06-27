package tests

import (
	"math/rand"
	"sync"
	"testing"
	"time"

	aba "github.com/GarryFCR/ADKG/aba"
	br "github.com/GarryFCR/ADKG/broadcast"
)

var wg2 sync.WaitGroup

func TestAba(t *testing.T) {

	//communication channels
	var chans [8]chan br.Message
	for j := range chans {
		chans[j] = make(chan br.Message, 100)
	}
	rand.Seed(time.Now().UnixNano())
	bits := new(int)
	for i := 0; i < 8; i++ {
		wg2.Add(1)
		/*vote := rand.Intn(2)
		fmt.Println(i, "'s proposal:", vote)*/
		go bin_agree(i%2, i, 8, 3, 3, bits, chans[:])
	}
	wg2.Wait()
	if *bits != 8 && *bits != -8 {
		t.Fatalf("ABA failed")
	}
}

func bin_agree(vote, id, n, k, j int,
	bits *int,
	chans []chan br.Message) {

	decision, _ := aba.Propose(vote, id, n, k, j, chans)
	if decision == 1 {
		*bits += 1
	} else {
		*bits -= 1
	}
	wg2.Done()

}
