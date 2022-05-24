package secretsharing

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/coinbase/kryptology/pkg/core/curves"
	feld "github.com/coinbase/kryptology/pkg/sharing"
	rs "github.com/vivint/infectious"

	br "github.com/GarryFCR/ADKG/broadcast"

	"crypto/elliptic"
	"crypto/rand"

	"gitlab.com/elktree/ecc"
)

var wg sync.WaitGroup

func Generate(n int) ([]*ecc.PrivateKey, []*ecc.PublicKey) {
	// generating p256 keys for identification and encryption
	privKeys := make([]*ecc.PrivateKey, n)
	pubKeys := make([]*ecc.PublicKey, n)
	for i := 0; i < n; i++ {
		pubKeys[i], privKeys[i], _ = ecc.GenerateKeys(elliptic.P256())
	}
	return privKeys, pubKeys
}

func FeldPolyCommit(n, k uint32, s int) (*feld.FeldmanVerifier, []*feld.ShamirShare) {

	//Using secp256k curve for other operations
	//Set the curve
	curve := curves.K256()
	//set the commitment
	f, _ := feld.NewFeldman(k, n, curve)

	scalar := curve.NewScalar()
	secret := scalar.New(s)
	feldcommit, shares, _ := f.Split(secret, rand.Reader)

	//fmt.Println(feldcommit, shares, err)
	return feldcommit, shares

}
func byte_2_shamirshare(ss []byte) *feld.ShamirShare {

	return &feld.ShamirShare{Id: binary.BigEndian.Uint32(ss[:4]), Value: ss[4:]}

}
func predicate(
	sk *ecc.PrivateKey,
	verifier *feld.FeldmanVerifier,
	c []byte,
	k, i int, //threshold
	chans []chan br.Message) bool {

	plaintext, err := sk.Decrypt(c[((k * 33) + (i * 150)) : ((k*33)+(i*150))+150])
	if err != nil {

		return false
	}

	ss := byte_2_shamirshare(plaintext)

	if verifier.Verify(ss) == nil {
		return true
	}
	return false

}

//todo: need to decode verifier from the broadcasted value
func Sharing_phase(
	secret int,
	n, k, leader uint32,
	chans []chan br.Message,
	priv []*ecc.PrivateKey,
	pub []*ecc.PublicKey) ([]byte, *feld.FeldmanVerifier) {

	Verifier, Shares := FeldPolyCommit(n, k, secret)

	c := make([]byte, 0)
	for _, v := range Verifier.Commitments {
		e := v.ToAffineCompressed() //33bytes
		c = append(c, e[:]...)
	}
	for i, s := range Shares {
		s1 := s.Bytes()
		//just to make an incorrect share of node 5
		/*
			if i+1 == 5 {
				fmt.Println(s)
				s1[len(s1)-1] = byte(0)
			}*/
		/////////////////////////////
		e, _ := pub[i].Encrypt(s1) //150 bytes
		c = append(c, e[:]...)

	}

	output := br.Rbc(priv, Verifier, chans, c, int(n), int(k-1), int(leader), predicate)

	for _, o := range output {
		if o != string(c) {
			fmt.Println("Incorrect value was recieved from the broadcast")
		}
	}
	return c, Verifier
}

//todo: handle multiple implicate message
//todo: extract c from the output message
func implicate_phase(
	i, k int,
	chans chan br.Message,
	pub []*ecc.PublicKey,
	verifier *feld.FeldmanVerifier,
	c []byte) (int, error) {

	output := br.Message{Msgtype: "done"}
	recovery := br.Message{Msgtype: "done"}
	sender := make([]int, 2)
	var done bool
	for {
		done = false
		select {
		case x, ok := <-chans:
			if ok {
				if x.Msgtype == "IMPLICATE" {
					priv, _ := ecc.UnmarshalPrivateKey(x.Output)
					if priv.Key.PublicKey.X.Cmp(*&pub[x.Sender].Key.X) == 0 && priv.Key.PublicKey.Y.Cmp(*&pub[x.Sender].Key.Y) == 0 && priv.Key.PublicKey.Curve == *&pub[x.Sender].Key.Curve {
						pos := ((k * 33) + (x.Sender * 150))
						plaintext, _ := priv.Decrypt(c[pos : pos+150])

						ss := byte_2_shamirshare(plaintext)

						if verifier.Verify(ss) != nil {
							//Indication to start recovery
							recovery = br.Message{
								Sender:  i,
								Msgtype: "RECOVERY",
								Value:   rs.Share{},
								Hash:    nil,
								Output:  x.Output}
							sender[0], sender[1] = 1, x.Sender
						}
					}
				} else if x.Msgtype == "OUTPUT" {
					output = x
				} else {
					continue
				}
			}
		default:
			done = true
		}
		if done {
			break
		}
	}
	//Indication that recovery is needed
	if recovery.Msgtype != "done" {
		chans <- recovery
	}
	//if only output is send to the channel no recovery is needed
	if output.Msgtype != "done" {
		chans <- output
	}
	if sender[0] == 1 {
		return sender[1], errors.New("Need to recover")
	}
	return 0, nil

}

func recovery_phase1(chans []chan br.Message, i int, sk *ecc.PrivateKey) {

	recovery := br.Message{Msgtype: "done"}
	done := false
	//At this point only recovery and/or output messages are there in the channels
	for j := 0; j < 2; j++ {
		select {
		case x, ok := <-chans[i]:
			if ok {
				if x.Msgtype == "RECOVERY" {
					recovery = x

				} else if x.Msgtype == "OUTPUT" {
					chans[i] <- x

					if recovery.Msgtype != "done" {
						priv, _ := sk.Marshal()
						br.Broadcast(chans, br.Message{
							Sender:  i,
							Msgtype: "SECRETKEY",
							Value:   rs.Share{},
							Hash:    nil,
							Output:  priv})
						time.Sleep(3 * time.Second)
					} else {
						done = true
					}

				}
			}
		default:
			done = true
		}
		if done {
			break
		}
	}

	wg.Done()

}

//nodes with no correct shares should run this
func recovery_phase2(
	n, k, share_id int,
	chans chan br.Message,
	c []byte,
	verifier *feld.FeldmanVerifier) (*feld.ShamirShare, error) {

	Shares := make([][]byte, 0)
	done := false
	//At this point only secretkey and/or output messages are there in the channels
	for {
		select {
		case x, ok := <-chans:
			if ok {
				if x.Msgtype == "SECRETKEY" {
					priv, _ := ecc.UnmarshalPrivateKey(x.Output)
					pos := ((k * 33) + (x.Sender * 150))
					plaintext, _ := priv.Decrypt(c[pos : pos+150])
					ss := byte_2_shamirshare(plaintext)

					if verifier.Verify(ss) == nil {
						Shares = append(Shares, plaintext)
					}
				} else if x.Msgtype == "OUTPUT" {
					done = true
				}
			}
		default:
			done = true
		}
		if done {
			break
		}
	}

	return recover_share(n, k, share_id, Shares)
}

func recover_share(n, k, share_id int, shares [][]byte) (*feld.ShamirShare, error) {

	if len(shares) < k {
		return nil, fmt.Errorf("invalid number of shares")
	}
	dups := make(map[uint32]bool, len(shares))
	xs := make([]curves.Scalar, len(shares))
	ys := make([]curves.Scalar, len(shares))
	curve := curves.K256()

	scalar := curve.NewScalar()
	x := scalar.New(share_id)
	for i, share := range shares {

		shamir_share := byte_2_shamirshare(share)
		err := shamir_share.Validate(curve)
		if err != nil {
			return nil, err
		}
		if shamir_share.Id > uint32(n) {
			return nil, fmt.Errorf("invalid share identifier")
		}
		if _, in := dups[shamir_share.Id]; in {
			return nil, fmt.Errorf("duplicate share")
		}
		dups[shamir_share.Id] = true
		ys[i], _ = curve.Scalar.SetBytes(shamir_share.Value)
		xs[i] = curve.Scalar.New(int(shamir_share.Id))
	}

	y := curve.Scalar.Zero()
	for i, xi := range xs {
		num := curve.Scalar.One()
		den := curve.Scalar.One()
		for j, xj := range xs {
			if i == j {
				continue
			}
			num = num.Mul(x.Sub(xj))
			den = den.Mul(xi.Sub(xj))
		}
		if den.IsZero() {
			return nil, fmt.Errorf("divide by zero")
		}
		y = y.Add(ys[i].Mul(num.Div(den)))
	}

	var ss [4]byte
	binary.BigEndian.PutUint32(ss[:], uint32(share_id))
	return byte_2_shamirshare(append(ss[:], y.Bytes()...)), nil

}

func reconstruct_phase1(k, id int, chans []chan br.Message, priv *ecc.PrivateKey, verifier *feld.FeldmanVerifier) {

	done := false
	for {
		select {
		case x, ok := <-chans[id]:
			if ok {
				if x.Msgtype == "OUTPUT" {
					chans[id] <- x
					pos := ((k * 33) + (x.Sender * 150))
					plaintext, _ := priv.Decrypt(x.Output[pos : pos+150])
					ss := byte_2_shamirshare(plaintext)

					if verifier.Verify(ss) == nil {
						br.Broadcast(chans, br.Message{
							Sender:  x.Sender,
							Msgtype: "RECONSTRUCT",
							Value:   rs.Share{},
							Hash:    nil,
							Output:  plaintext /*share*/})
						time.Sleep(3 * time.Second)

						done = true
					}
				}
			}
		default:
			done = true
		}
		if done {
			break
		}
	}

}

//We make a change were we only send the share to the node that calls reconstruct
func reconstruct_phase2(
	n, k, id int,
	chans []chan br.Message,
	priv *ecc.PrivateKey,
	verifier *feld.FeldmanVerifier) {

	output := br.Message{Msgtype: "done"}
	reconstruct := br.Message{Msgtype: "done"}
	done := false
	//At this point there is a reconstruct message and a output message
	for {
		select {
		case x, ok := <-chans[id]:
			if ok {
				if x.Msgtype == "RECONSTRUCT" {
					ss := byte_2_shamirshare(x.Output)
					if verifier.Verify(ss) == nil {
						reconstruct = x

					} else {
						done = true
					}
				} else if x.Msgtype == "OUTPUT" {
					output = x
				} else {
					continue
				}
			}
		default:
			done = true
		}
		if done {
			break
		}

	}

	if reconstruct.Msgtype != "done" && output.Msgtype != "done" {

		chans[id] <- output

		pos := ((k * 33) + (id * 150))
		plaintext, _ := priv.Decrypt(output.Output[pos : pos+150])

		chans[reconstruct.Sender] <- br.Message{
			Sender:  id,
			Msgtype: "RECONSTRUCT",
			Value:   rs.Share{},
			Hash:    nil,
			Output:  plaintext /*share*/}
	}
	if reconstruct.Msgtype == "done" && output.Msgtype != "done" {
		chans[id] <- output
	}

	wg.Done()
}

func reconstruct_phase3(
	n, k uint32,
	chans chan br.Message,
	verifier *feld.FeldmanVerifier) (curves.Scalar, error) {

	//At this point the node that called for reconstruct  has  reconstruct messages and an output message
	T := make([]*feld.ShamirShare, 0)
	output := br.Message{Msgtype: "done"}
	done := false
	for {
		select {
		case x, ok := <-chans:
			if ok {
				if x.Msgtype == "RECONSTRUCT" {
					ss := byte_2_shamirshare(x.Output)
					if verifier.Verify(ss) == nil {
						T = append(T, ss)

					}
				} else if x.Msgtype == "OUTPUT" {
					output = x
				}
			}
		default:
			done = true
		}
		if done {
			break
		}
	}

	if output.Msgtype != "done" {
		chans <- output
	}
	if len(T) >= int(k) {
		f, _ := feld.NewFeldman(k, n, curves.K256())
		secret, _ := f.Combine(T...)
		return secret, nil
	}
	return nil, errors.New("not enough shares")

}

func Acss(secret int, n, k, leader uint32, chans []chan br.Message) {
	priv, pub := Generate(int(n))

	//SHARING PHASE ----------------------------------------------------
	fmt.Println("Sharing Phase------------------------------------------")
	c, verifier := Sharing_phase(secret, n, k, leader, chans, priv, pub)

	//IMPLICATION PHASE ------------------------------------------------
	//Implicate phase needs to be done by all nodes
	count := make(map[int]int)
	for i := 0; i < int(n); i++ {
		id, err := implicate_phase(i, int(k), chans[i], pub, verifier, c)
		if err != nil {
			count[id]++
		}
	}
	//RECOVERY PHASE ----------------------------------------------------
	if len(count) != 0 {
		fmt.Println("Recovery Phase--------------------------------------")
	}
	for pos, v := range count {
		if v > int(k) {
			//Check recovery message at all nodes
			for i := 0; i < int(n); i++ {
				wg.Add(1)
				go recovery_phase1(chans, i, priv[i])
			}
			wg.Wait()

			//Let the node that didnt get the share run this part
			share, err := recovery_phase2(int(n), int(k), pos+1, chans[pos], c, verifier)
			if err != nil {
				panic(err)
			} else {
				fmt.Println(share)
			}

		}
	}

	//RECONSTRUCT PHASE --------------------------------------------------
	fmt.Println("Reconstruct Phase----------------------------------------")
	//Send reconstruct message by node 3
	reconstruct_phase1(int(k), 3, chans, priv[3], verifier)
	//Start sharing of shares
	for i := 0; i < int(n); i++ {
		if i == 3 {
			continue
		}
		wg.Add(1)
		go reconstruct_phase2(int(n), int(k), i, chans, priv[i], verifier)
	}
	wg.Wait()
	//Start reconstructing
	result, err := reconstruct_phase3(n, k, chans[3], verifier)
	if err == nil {
		y := curves.K256().NewScalar().New(100) // 100 in scalar form
		if result.Cmp(y) == 0 {
			fmt.Println("Correct Reconstruction")
		}
	}

}
