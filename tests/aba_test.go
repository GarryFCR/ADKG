package tests

import (
	"sync"
	"testing"

	aba "github.com/GarryFCR/ADKG/aba"
	br "github.com/GarryFCR/ADKG/broadcast"
	"github.com/coinbase/kryptology/pkg/core/curves"
	feld "github.com/coinbase/kryptology/pkg/sharing"
)

var wg2 sync.WaitGroup

func TestAba(t *testing.T) {

	//communication channels
	var chans [7]chan br.Message
	for j := range chans {
		chans[j] = make(chan br.Message, 100)
	}
	//rand.Seed(time.Now().UnixNano())
	bits := new(int)
	for i := 0; i < 7; i++ {
		wg2.Add(1)
		/*vote := rand.Intn(2)
		fmt.Println(i, "'s proposal:", vote)*/
		go bin_agree(i%2, i, 7, 3, bits, chans[:])
	}
	wg2.Wait()
	if *bits != 7 && *bits != -7 {
		t.Fatalf("ABA failed")
	}
}

func bin_agree(vote, id, n, k int,
	bits *int,
	chans []chan br.Message) {

	S_i := make([]*feld.ShamirShare, 0)
	C_i := make(map[int][]curves.Point, 0)
	T_i := make([]int, 0)
	curve := curves.K256()

	decision, _ := aba.Propose(vote, id, n, k, chans, curve, 1, S_i, T_i, C_i)
	if decision == 1 {
		*bits += 1
	} else {
		*bits -= 1
	}
	wg2.Done()

}
