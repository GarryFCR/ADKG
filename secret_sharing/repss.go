// Package secretsharing Implements ADKG and RepSS
package secretsharing

import (
	"fmt"

	feld "github.com/coinbase/kryptology/pkg/sharing"
	sharingv1 "github.com/coinbase/kryptology/pkg/sharing/v1"

	br "github.com/GarryFCR/ADKG/broadcast"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"gitlab.com/elktree/ecc"
)

type share struct {
	index  int
	secret int
	pk     *ecc.PublicKey
	sk     *ecc.PrivateKey
	ch     chan br.Message
}

// func (v FeldmanVerifier) VerifyHomomorphic(share *ShamirShare) error {
// 	curve := curves.GetCurveByName(v.Commitments[0].CurveName())
// 	err := share.Validate(curve)
// 	if err != nil {
// 		return err
// 	}
// 	x := curve.Scalar.New(int(share.Id))
// 	i := curve.Scalar.One()
// 	rhs := v.Commitments[0]

// 	for j := 1; j < len(v.Commitments); j++ {
// 		i = i.Mul(x)
// 		rhs = rhs.Add(v.Commitments[j].Mul(i))
// 	}
// 	sc, _ := curve.Scalar.SetBytes(share.Value)
// 	lhs := v.Commitments[0].Generator().Mul(sc)

// 	if lhs.Equal(rhs) {
// 		return nil
// 	} else {
// 		return fmt.Errorf("not equal")
// 	}
// }

func agreementPhase(lost share, nodes []share) []share { return make([]share, 0) }

func enrollmentPhase(lost share, nodes []share, threshold int) share {
	lagrangeCoefficient := func(node share, x int) int {
		result := 1
		i := node.index
		for _, n := range nodes {
			j := n.index
			if j != i {
				result *= (x - j) / (i - j)
			}
		}
		return result
	}
	/////// BOILERPLATE:
	pks := make([]*ecc.PublicKey, len(nodes))
	for i, n := range nodes {
		if i+1 == n.index {
			pks[i] = n.pk
		}
	}
	sks := make([]*ecc.PrivateKey, len(nodes))
	for i, n := range nodes {
		if i+1 == n.index {
			sks[i] = n.sk
		}
	}
	chans := make([]chan br.Message, len(nodes))
	for i, n := range nodes {
		if i+1 == n.index {
			chans[i] = n.ch
		}
	}
	// pretend this works
	recv := func(chan br.Message) ([][]curves.PointK256, []sharingv1.ShamirShare) {
		ps := make([][]curves.PointK256, 0)
		sh := []sharingv1.ShamirShare{{1, &curves.K256().Scalar}}
		return ps, sh
	}
	///////////////////////
	for _, n := range nodes {
		l := lagrangeCoefficient(n, lost.index)
		r := (l * n.secret)

		// share value with polynomials
		Acss(r, uint32(len(nodes)), uint32(threshold), uint32(n.index), chans, sks, pks)
		//verifier, shares := FeldPolyCommit(len(nodes), threshold, r)
		//commitments := verifier.Commitments

		// wait to receive all others' values
		commitments, shares := recv(chans[n.index])

		// join commitments and share into one
		commitment, share := make([]curves.PointK256, 1), sharingv1.NewShamirShare(1, []byte{}, curves.K256())
		for _, c := range commitments {
			for i := range commitment {
				commitment[i].Add(&c[i]) // g^{a_i} * g^{b_i} * ,,,
			}
		}
		for _, s := range shares {
			if share.Id != s.Id {
				panic("no")
			}
			share.Add(s)
		}

		// CHECK combined ACSS SHARES
		feld.FeldmanVerifier{commitments}.Verify(share)

		// send combined ACSS shares
		fmt.Println("send(...)")
	}
	// new node get shares
	commitments, shares := recv(chans[lost.index])

	// CHECK combined ACSS SHARES, should ignore rather than implicate...
	feld.FeldmanVerifier{commitments}.Verify(share)

	//reconstruct Joined ACSS
	//F, _ := feld.NewFeldman(uint32(threshold), uint32(len(nodes)), curves.K256())
	//secret, _ := F.Combine(shares...)
	secret := 0
	lost.secret = secret
}

func disenrollmentPhase(lost share, nodes []share, threshold int) {
	/////// BOILERPLATE:
	pks := make([]*ecc.PublicKey, len(nodes))
	for i, n := range nodes {
		if i+1 == n.index {
			pks[i] = n.pk
		}
	}
	sks := make([]*ecc.PrivateKey, len(nodes))
	for i, n := range nodes {
		if i+1 == n.index {
			sks[i] = n.sk
		}
	}
	chans := make([]chan br.Message, len(nodes))
	for i, n := range nodes {
		if i+1 == n.index {
			chans[i] = n.ch
		}
	}
	recv := func(chan br.Message) ([][]curves.PointK256, []sharingv1.ShamirShare) {
		ps := make([][]curves.PointK256, 0)
		sh := []sharingv1.ShamirShare{{1, make([]byte, 0)}}
		return ps, sh
	}
	///////////////////////
	good_nodes := nodes
	for _, n := range good_nodes {
		// share zero-polynomial with others
		g := 0
		Acss(g, uint32(len(nodes)), uint32(threshold), uint32(n.index), chans, sks, pks) // is threshold correct?

		// receive other people's polynomals
		commitments, shares := recv(chans[lost.index])

		// CHECK normal ACSS SHARES, ensure they come from good_nodes, and implicate if anything is wrong
		fmt.Println("get help from garry", commitments)
		fmt.Println("filter out shares from the wrong parties", shares)
		if false {
			panic("implicate just like ADKG/ACSS implicate")
		}

		// add up the shares, and double-check it's all good
		commitment, share := make([]curves.PointK256, 1), sharingv1.ShamirShare{1, make([]byte, 0)}
		for _, c := range commitments {
			for i := range commitment {
				commitment[i].Add(&c[i])
			}
		}
		for _, s := range shares {
			if share.Id != s.Id {
				panic("no")
			}
			for i := range share.Value {
				share.Value[i] += s.Value[i] // totally incorrect!
			}
		}

		// CHECK combined ACSS SHARES
		fmt.Println("get help from garry")

		// put in the new share, IF all is good with the others
		n.secret = 0
	}

}

// Function implements RepairableSS for our ADKG system
// "lost" is the node we're recovering/disenrolling
// "nodes" is the list of nodes in the network
// "threshold" is an internal value required by our ACSS
func RepShare(lost share, nodes []share, threshold int) {
	//nodes = agreementPhase(lost, nodes)
	new_node := enrollmentPhase(lost, nodes, threshold)
	good_nodes = agreementPhase(lost, nodes)
	disenrollmentPhase(lost, good_nodes, threshold)
}
