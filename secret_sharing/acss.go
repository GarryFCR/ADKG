package secretsharing

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/coinbase/kryptology/pkg/core/curves"
	feld "github.com/coinbase/kryptology/pkg/sharing"
	rs "github.com/vivint/infectious"

	br "github.com/GarryFCR/ADKG/broadcast"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
)

var wg sync.WaitGroup
var wg1 sync.WaitGroup

//Generate key pairs
func Generate(curve *curves.Curve, n int) ([]curves.Scalar, []curves.Point) {

	privKeys := make([]curves.Scalar, n)
	pubKeys := make([]curves.Point, n)
	for i := 0; i < n; i++ {
		g := curve.NewGeneratorPoint()
		sk_i := curve.NewScalar().Random(rand.Reader)
		pk_i := g.Mul(sk_i)
		pubKeys[i], privKeys[i] = pk_i, sk_i
	}
	return privKeys, pubKeys
}
func Getpubk(curve *curves.Curve, n int) []curves.Point {
	file, err := os.Open("./NodeKeys/Pubkey.txt")
	if err != nil {
		panic(err)
	}

	defer file.Close()
	pub := make([]curves.Point, 0)
	for i := 0; i < n; i++ {
		file.Seek(int64(i*33), 0)
		b := make([]byte, 33)
		file.Read(b)
		pubk, _ := curve.Point.FromAffineCompressed(b)
		pub = append(pub, pubk)
	}

	return pub
}
func getPolyAndShares(
	secret curves.Scalar,
	threshold, limit uint32,
	curve *curves.Curve,
	reader io.Reader) ([]*feld.ShamirShare, *feld.Polynomial) {
	poly := new(feld.Polynomial).Init(secret, threshold, reader)
	shares := make([]*feld.ShamirShare, limit)
	for i := range shares {
		x := curve.Scalar.New(i + 1)
		shares[i] = &feld.ShamirShare{
			Id:    uint32(i + 1),
			Value: poly.Evaluate(x).Bytes(),
		}
	}
	return shares, poly
}

func Splitt(
	secret curves.Scalar,
	threshold, limit uint32,
	curve *curves.Curve,
	reader io.Reader) (*feld.FeldmanVerifier, []*feld.ShamirShare, error) {

	shares, poly := getPolyAndShares(secret, threshold, limit, curve, reader)
	verifier := new(feld.FeldmanVerifier)
	verifier.Commitments = make([]curves.Point, threshold)
	for i := range verifier.Commitments {
		verifier.Commitments[i] = curve.ScalarBaseMult(poly.Coefficients[i])
	}
	return verifier, shares, nil
}

//Generate Feldman commitment and shamir shares
func FeldPolyCommit(n, k uint32, s curves.Scalar, curve *curves.Curve) (*feld.FeldmanVerifier, []*feld.ShamirShare) {

	//set the commitment
	f, _ := feld.NewFeldman(k, n, curve)

	feldcommit, shares, err := Splitt(s, f.Threshold, f.Limit, f.Curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	return feldcommit, shares

}

//Convert bytes to shamir shares
func Byte_2_shamirshare(ss []byte) *feld.ShamirShare {

	return &feld.ShamirShare{Id: binary.BigEndian.Uint32(ss[:4]), Value: ss[4:]}

}

//predicate that needs to be satisfied in reliable broadcast
func predicate(
	shared_symkey []byte,
	//verifier *feld.FeldmanVerifier,
	c []byte,
	k, i int, //threshold
	curve *curves.Curve,
	chans []chan br.Message) bool {

	//plaintext, err := sk.Decrypt(c[((k * 33) + (i * 150)) : ((k*33)+(i*150))+150])
	pt := c[((k * 33) + (i * 52)) : ((k*33)+(i*52))+52]
	plaintext := DecryptAES(shared_symkey, pt)

	ss := Byte_2_shamirshare(plaintext)

	verifier, err := Get_verifier(k, c, curve)
	if err != nil {
		return false
	}
	if verifier.Verify(ss) == nil {
		return true
	}
	return false

}

//get the commitment from the broadcasted value(v||c in paper)  sharing phase
func Get_verifier(k int, c []byte, curve *curves.Curve) (*feld.FeldmanVerifier, error) {

	commitment := make([]curves.Point, 0)
	//point := new(curves.PointK256)
	for i := 0; i < k; i++ {
		c_i, err := curve.Point.FromAffineCompressed(c[i*33 : (i*33)+33])
		if err == nil {
			commitment = append(commitment, c_i)
		} else {
			return nil, err
		}
	}

	verifier := new(feld.FeldmanVerifier)
	verifier.Commitments = commitment
	return verifier, nil
}
func EncryptAES(key []byte, plaintext []byte) []byte {

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext
}

func DecryptAES(key []byte, ciphertext []byte) []byte {

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext
}

func verify_NIZK(
	pk_i, pk_d, K_i curves.Point,
	curve *curves.Curve,
	proof []byte) bool {

	g := curve.NewGeneratorPoint()
	s, _ := curve.Scalar.SetBytes(proof[:32])
	e, _ := curve.Scalar.SetBytes(proof[32:])

	a := g.Mul(s).Add(pk_i.Mul(e))
	b := pk_d.Mul(s).Add(K_i.Mul(e))

	bs := []byte{}
	input := []curves.Point{g, pk_d, pk_i, K_i, a, b}
	for _, P := range input {
		bs = append(bs, P.ToAffineCompressed()...)
	}
	if curve.NewScalar().Hash(bs).Cmp(e) == 0 {
		return true
	}
	return false
}

func Sharing_phase(
	secret curves.Scalar,
	n, k, leader, sid uint32,
	sk_d curves.Scalar,
	pk_d curves.Point,
	curve *curves.Curve,
	chans []chan br.Message) []byte {

	Verifier, Shares := FeldPolyCommit(n, k, secret, curve)

	c := make([]byte, 0)
	for _, v := range Verifier.Commitments {
		e := v.ToAffineCompressed() //33bytes
		c = append(c, e[:]...)
	}
	pub := Getpubk(curve, int(n))
	for i, s := range Shares {
		s1 := s.Bytes() // 36 bytes

		//just to make an incorrect share of node 5
		/*
			if i+1 == 5 {
				fmt.Println("Changing share of node", i, ":", s)
				s1[len(s1)-1] = byte(0)
			}*/
		/////////////////////////////
		//Using shared key for encrypting (long term key use)
		K_i := pub[i].Mul(sk_d)
		shared_symkey := sha256.Sum256(K_i.ToAffineCompressed())

		e := EncryptAES(shared_symkey[:], s1) // 52 bytes
		c = append(c, e[:]...)

	}
	//Add pk_d to the ReliableBroadcast message in sharing phase .
	c = append(c, pk_d.ToAffineCompressed()...)

	output := br.Rbc(chans, c, int(n), int(k-1), int(leader), int(sid), curve, pk_d, predicate, "ACSS")
	for i, o := range output {
		if o != string(c) {
			fmt.Println("Incorrect value was recieved from the broadcast by:", i)

		}
	}

	return c
}

//checking if anyone got an incorrect shares through an implicate message
func implicate_phase(
	n, i, k, sid int,
	chans chan br.Message,
	pk_d curves.Point,
	curve *curves.Curve,
	c []byte) (int, error) {

	output := br.Message{Msgtype: "done"}
	recovery := br.Message{Msgtype: "done"}
	sender := make([]int, 2)
	var done bool
	verifier, _ := Get_verifier(k, c, curve)
	pub := Getpubk(curve, n)
	for {
		done = false
		select {
		case x, ok := <-chans:
			if ok {
				//todo: need to make sure when to stop listening to the channel instead of waiting till the channel is empty
				if x.Msgtype == "IMPLICATE" {
					K_i, _ := curve.Point.FromAffineCompressed(x.Output)
					pk_i := pub[x.Sender]

					if verify_NIZK(pk_i, pk_d, K_i, curve, x.Hash) {
						pos := ((k * 33) + (x.Sender * 52))
						key := sha256.Sum256(x.Output)
						plaintext := DecryptAES(key[:], c[pos:pos+52])

						ss := Byte_2_shamirshare(plaintext)
						if verifier.Verify(ss) != nil {
							//Indication to start recovery
							recovery = br.Message{
								Sender:  i,
								Sid:     sid,
								Msgtype: "RECOVERY",
								Value:   rs.Share{},
								Hash:    nil,
								Output:  x.Output}
							sender[0], sender[1] = 1, x.Sender
						}
					}
				} else if x.Msgtype == "OUTPUT" && x.Sid == sid {
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
	//note that the order in which we input  to channel is important
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

//Sharing private key if there is a recovery
func recovery_phase1(curve *curves.Curve, chans []chan br.Message, id, sid int, pk_d curves.Point) {

	output := br.Message{Msgtype: "done"}
	recovery := br.Message{Msgtype: "done"}
	sk_i := br.Getprivk(curve, id)
	done := false
	for {
		select {
		case x, ok := <-chans[id]:
			if ok {
				if x.Msgtype == "RECOVERY" {
					recovery = x

				} else if x.Msgtype == "OUTPUT" {
					output = x
				} else if recovery.Msgtype != "done" && output.Msgtype != "done" {
					done = true
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

	if recovery.Msgtype != "done" {
		K_i := pk_d.Mul(sk_i)
		br.Broadcast(chans, br.Message{
			Sender:  id,
			Sid:     sid,
			Msgtype: "SECRETKEY",
			Value:   rs.Share{},
			Hash:    nil,
			Output:  K_i.ToAffineCompressed()})
	}
	if output.Msgtype != "done" {
		chans[id] <- output
	}

	wg.Done()

}

//nodes with an incorrect share should run this
func recovery_phase2(
	n, k, share_id, sid int,
	chans chan br.Message,
	curve *curves.Curve,
	c []byte) (*feld.ShamirShare, error) {

	Shares := make([][]byte, 0)
	output := br.Message{Msgtype: "done"}

	verifier, _ := Get_verifier(k, c, curve)

	done := false
	//At this point only secretkey and/or output messages are there in the channels
	for {
		select {
		case x, ok := <-chans:
			if ok {
				if x.Msgtype == "SECRETKEY" {

					pos := ((k * 33) + (x.Sender * 52))
					key := sha256.Sum256(x.Output)
					plaintext := DecryptAES(key[:], c[pos:pos+52])

					ss := Byte_2_shamirshare(plaintext)

					if verifier.Verify(ss) == nil {
						Shares = append(Shares, plaintext)
					}
				} else if x.Msgtype == "OUTPUT" {
					output = x
				} else if len(Shares) > k {
					done = true
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

	if output.Msgtype != "done" {
		chans <- output
	}

	return recover_share(n, k, share_id, Shares)
}

//Generate shamir share for a given node when we have threshold number of shares to regenerate the polynomial
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

		shamir_share := Byte_2_shamirshare(share)
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
	return Byte_2_shamirshare(append(ss[:], y.Bytes()...)), nil

}

//Send reconstruct message to all
func reconstruct_phase1(n, k, id, sid int, curve *curves.Curve, chans []chan br.Message) {

	done := false
	for {
		select {
		case x, ok := <-chans[id]:
			if ok {
				if x.Msgtype == "OUTPUT" {
					chans[id] <- x

					pk_d, _ := curve.Point.FromAffineCompressed(x.Output[(k*33)+(n*52) : (k*33)+(n*52)+33])
					sk_i := br.Getprivk(curve, id)
					K_i := pk_d.Mul(sk_i)
					pos := ((k * 33) + (x.Sender * 52))
					key := sha256.Sum256(K_i.ToAffineCompressed())
					plaintext := DecryptAES(key[:], x.Output[pos:pos+52])
					ss := Byte_2_shamirshare(plaintext)
					verifier, _ := Get_verifier(k, x.Output, curve)

					if verifier.Verify(ss) == nil {
						br.Broadcast(chans, br.Message{
							Sender:  x.Sender,
							Sid:     sid,
							Msgtype: "RECONSTRUCT",
							Value:   rs.Share{},
							Hash:    nil,
							Output:  plaintext /*share*/})

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

//Sending share to the node that called reconstruct
func reconstruct_phase2(
	n, k, id, sid int,
	curve *curves.Curve,
	chans []chan br.Message,
	c []byte) {

	output := br.Message{Msgtype: "done"}
	reconstruct := br.Message{Msgtype: "done"}
	done := false
	//At this point there is a reconstruct message and a output message
	verifier, _ := Get_verifier(k, c, curve)
	for {
		select {
		case x, ok := <-chans[id]:
			if ok {
				if x.Msgtype == "RECONSTRUCT" {
					ss := Byte_2_shamirshare(x.Output)

					if verifier.Verify(ss) == nil {
						reconstruct = x

					} else {

						done = true
					}
				} else if x.Msgtype == "OUTPUT" && sid == x.Sid {
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

	if reconstruct.Msgtype != "done" && output.Msgtype != "done" {

		chans[id] <- output

		pk_d, _ := curve.Point.FromAffineCompressed(output.Output[(k*33)+(n*52) : (k*33)+(n*52)+33])

		sk_i := br.Getprivk(curve, id)
		K_i := pk_d.Mul(sk_i)
		pos := ((k * 33) + (id * 52))
		key := sha256.Sum256(K_i.ToAffineCompressed())
		plaintext := DecryptAES(key[:], output.Output[pos:pos+52])

		chans[reconstruct.Sender] <- br.Message{
			Sender:  id,
			Sid:     sid,
			Msgtype: "RECONSTRUCT",
			Value:   rs.Share{},
			Hash:    nil,
			Output:  plaintext /*share*/}
	}
	if reconstruct.Msgtype == "done" && output.Msgtype != "done" {
		chans[id] <- output
	}

	wg1.Done()
}

//Reconstruction of secret after collecting threshold shares
func reconstruct_phase3(
	n, k uint32,
	curve *curves.Curve,
	chans chan br.Message,
	c []byte) (curves.Scalar, error) {

	//At this point the node that called for reconstruct  has  reconstruct messages and an output message
	T := make([]*feld.ShamirShare, 0)
	output := br.Message{Msgtype: "done"}

	done := false
	verifier, _ := Get_verifier(int(k), c, curve)
	for {
		select {
		case x, ok := <-chans:
			if ok {
				if x.Msgtype == "RECONSTRUCT" {
					ss := Byte_2_shamirshare(x.Output)
					if verifier.Verify(ss) == nil {
						T = append(T, ss)

					}
				} else if x.Msgtype == "OUTPUT" {
					output = x
				} else if len(T) >= int(k) {
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

func Acss(
	secret curves.Scalar,
	n, k, leader, sid uint32,
	curve *curves.Curve,
	chans []chan br.Message) ([]byte, bool) {

	//Generate ephemeral key
	sk_d, pk_d := Generate(curve, 1)

	fmt.Println("ACSS for node-", leader, "started...")
	//SHARING PHASE ----------------------------------------------------
	c := Sharing_phase(secret, n, k, leader, sid, sk_d[0], pk_d[0], curve, chans)

	//IMPLICATION PHASE ------------------------------------------------
	//Implicate phase needs to be done by all nodes , basically checking if there is an implicate message
	fmt.Println("ACSS for node-", leader, "checking for implicate messages ...")
	count := make(map[int]int)
	for i := 0; i < int(n); i++ {
		id, err := implicate_phase(int(n), i, int(k), int(sid), chans[i], pk_d[0], curve, c)
		if err != nil {
			count[id]++
		}
	}
	//RECOVERY PHASE ----------------------------------------------------
	if len(count) == 0 {
		fmt.Println("ACSS completed for node-", leader, "...")

		return c, true
	}
	fmt.Println("Recovery Phase--------------------------------------")
	for pos, v := range count {
		if v > int(k) {
			//Check recovery message at all nodes
			for i := 0; i < int(n); i++ {
				wg.Add(1)
				go recovery_phase1(curve, chans, i, int(sid), pk_d[0])
			}
			wg.Wait()

			//The node that needs to recover share run this
			share, err := recovery_phase2(int(n), int(k), pos+1, int(sid), chans[pos], curve, c)
			if err != nil {
				panic(err)
			} else {
				fmt.Println("Recovered share of node ", pos, ":", share)
			}

		}
	}

	return c, false

}
func Acss_reconstruct(
	c []byte,
	n, k uint32,
	id, sid int,
	curve *curves.Curve,
	chans []chan br.Message,
) (curves.Scalar, error) {

	//RECONSTRUCT PHASE --------------------------------------------------
	fmt.Println("Reconstruct Phase----------------------------------------")
	fmt.Println("Node ", id, " calling for reconstruction...")
	reconstruct_phase1(int(n), int(k), int(id), int(sid), curve, chans)
	//Start sharing of shares

	for i := 0; i < int(n); i++ {
		if i == id {
			continue
		}
		wg1.Add(1)

		go reconstruct_phase2(int(n), int(k), i, sid, curve, chans, c)
	}
	wg1.Wait()
	//Start reconstructing
	result, err := reconstruct_phase3(n, k, curve, chans[id], c)
	return result, err
}
