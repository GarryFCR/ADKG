package Broadcast

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/coinbase/kryptology/pkg/core/curves"
	rs "github.com/vivint/infectious"
)

var wg sync.WaitGroup

//type fn func([]byte) bool
type fn func(
	symkey []byte,
	c []byte,
	k, i int,
	curve *curves.Curve,
	chans []chan Message) bool

type Message struct {
	Sender  int
	Sid     int // session id
	Msgtype string
	Value   rs.Share
	Hash    []byte
	Output  []byte
}

type payload struct {
	count int
	val   rs.Share
	hash  []byte
}

func Rs_enc(n int, k int, msg []byte) ([]rs.Share, *rs.FEC, error) {

	f, err := rs.NewFEC(k, n)
	if err != nil {
		return nil, nil, err
	}

	shares := make([]rs.Share, n)
	output := func(s rs.Share) {
		shares[s.Number] = s.DeepCopy()
	}

	//the data to encode must be padded to a multiple of required
	if len(msg)%k != 0 {
		for len(msg)%k != 0 {
			msg = append(msg, byte(0))
		}
	}

	err = f.Encode(msg, output)
	if err != nil {
		return nil, nil, err
	}

	return shares, f, nil
}

func Rs_dec(n int, k int, shares []rs.Share, f *rs.FEC) ([]byte, error) {

	result, err := f.Decode(nil, shares)
	if err != nil {
		return nil, err
	}

	for {
		if result[len(result)-1] != 0 {
			return result, nil
		}
		result = result[:(len(result) - 1)]
	}
}

func Getprivk(curve *curves.Curve, id int) curves.Scalar {

	str1 := strconv.Itoa(id)
	str2 := "./NodeKeys/Privkey"
	filename := str2 + str1 + ".txt"
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	file.Seek(0, 0)
	b := make([]byte, 32)
	file.Read(b)
	privk, err := curve.Scalar.SetBytes(b)
	if err != nil {
		panic(err)
	}

	return privk

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
func Rbc(
	chans []chan Message,
	msg []byte,
	n, f, leader, sid int, //here f is the number of faulty parties
	curve *curves.Curve,
	pk_d curves.Point,
	predicate fn, tag string) []string {

	Output := make([]string, n)
	for i := 0; i < n; i += 1 {
		wg.Add(1)
		go Run_rbc(n, f, sid, chans[:], leader, msg, i, predicate, pk_d, curve, Output, tag)
	}
	wg.Wait()
	return Output
}

func hash(msg []byte) []byte {
	sum := sha256.Sum256(msg)
	return sum[:]
}

func Broadcast(ch []chan Message, msg Message) {

	for _, c := range ch {
		go send(c, msg)
	}
}

func send(ch chan Message, msg Message) {

	ch <- msg
}

//todo : recieve should only be available to  specific nodes
func recieve(ch chan Message) Message {
	value := <-ch
	return value
}

func gen_NIZK(
	g, pk_i, pk_d, K_i curves.Point,
	sk_i curves.Scalar) []byte { // maybe enforce specific curve points K256Point and scalar K256Scalar

	Commit := func(g, h curves.Point) ([]curves.Point, curves.Scalar) {
		k := curves.K256().NewScalar().Random(rand.Reader)
		return []curves.Point{g.Mul(k), h.Mul(k)}, k
	}
	Challenge := func(public_inputs, r []curves.Point) curves.Scalar {
		bs := []byte{}
		for _, P := range append(public_inputs, r...) {
			bs = append(bs, P.ToAffineCompressed()...)
		}
		return curves.K256().NewScalar().Hash(bs) // is this a cryptographic hash cipher with output the size of our field?
	}
	Response := func(x, k, e curves.Scalar) curves.Scalar {
		return k.Sub(e.Mul(x))
	}
	// Chaum-Pedersen: prove: g^x = y1 && h^x = y2
	g, h, y1, y2, x := g, pk_d, pk_i, K_i, sk_i
	public_inputs := []curves.Point{g, h, y1, y2}
	for _, P := range public_inputs { // check everything in curve.
		if !P.IsOnCurve() { // are we checking it's a K256 curve or just generic?
			panic(fmt.Sprintf("PROOF INPUT(s) INVALID: %v is not on the Curve!", P.ToAffineCompressed()))
		}
	}

	r, k := Commit(g, h)
	e := Challenge(public_inputs, r)
	s := Response(x, k, e)

	public_inputs_byte := make([]byte, 0)
	public_inputs_byte = append(public_inputs_byte, s.Bytes()...)                 // s is 32 bytes
	public_inputs_byte = append(public_inputs_byte, r[0].ToAffineCompressed()...) // 33 bytes
	public_inputs_byte = append(public_inputs_byte, r[1].ToAffineCompressed()...) // 33 bytes

	// s,r
	return public_inputs_byte

}

func Run_rbc(
	n, f, sid int,
	ch []chan Message,
	leader int,
	msg []byte,
	id int,
	predicate fn,
	pk_d curves.Point,
	curve *curves.Curve,
	Output []string,
	tag string) {

	//fmt.Println("Node -", id, "session id -", sid, "joined...")

	//Constraints
	if n < 3*f+1 || f < 0 || leader < 0 || leader > n || id < 0 || id > n || f < n/3 {
		wg.Done()
		panic(errors.New("Invalid parameter"))
	}

	echo_list := make([]payload, n)
	ready_list := make(map[int]payload)
	echo_counter := make(map[int]payload)
	var ready_hash []byte
	var ready_val rs.Share //[]byte
	ready_sent := false
	var T_h []rs.Share

	var fec *rs.FEC
	var M_i []rs.Share
	var err error
	//leader Broadcasts
	if leader == id {
		Broadcast(ch, Message{id, sid, "PROPOSE", rs.Share{Number: 0, Data: msg}, nil, nil})

	}

	for {

		text := recieve(ch[id])

		if text.Msgtype == "T_i" {
			go send(ch[id], text)
			continue
		}
		if text.Msgtype == "PROPOSE" {

			//fmt.Println("Node", id, "Receiving propose message...")
			sk_i := Getprivk(curve, id)
			K_i := pk_d.Mul(sk_i)
			shared_symkey := sha256.Sum256(K_i.ToAffineCompressed())
			tmp := append([]byte{}, text.Value.Data...)
			if text.Sender != leader {
				continue
			} else if predicate(shared_symkey[:], tmp, f+1, id, curve, ch) {

				h := hash(text.Value.Data)
				M_i, fec, err = Rs_enc(n, f+1, text.Value.Data)

				if err != nil {
					panic(err)
				}
				for i := range ch {
					go send(ch[i], Message{id, sid, "ECHO", M_i[i], h, nil})
				}

			} else if tag == "KEY SET PROPOSAL" {
				fmt.Println("Node", id, "not participating in", text.Sid, "rbc")
				wg.Done()
				return
			} else if tag == "ACSS" {

				pk_i := Getpubk(curve, n)[id]
				g := curve.NewGeneratorPoint()
				proof_argument := gen_NIZK(g, pk_i, pk_d, K_i, sk_i)
				time.Sleep(5 * time.Second)

				Broadcast(ch, Message{id, sid, "IMPLICATE", rs.Share{}, proof_argument, K_i.ToAffineCompressed()})
				fmt.Println("Invalid value by", id)
				fmt.Println("Sending implicate message...")

				wg.Done()
				return
			}

		} else if text.Msgtype == "ECHO" {

			//fmt.Println("Node", id, "Receiving echo messages...")
			//Checking for redundant echo Messages
			if echo_list[text.Sender].count >= 1 {
				continue
			}

			//storing echo Messages of each Sender
			echo_list[text.Sender] = payload{1, text.Value, text.Hash}

			//Counting the identical echo Messages sent by different Senders
			key, flag := 0, false
			if len(echo_counter) == 0 {
				echo_counter[0] = echo_list[text.Sender]
				flag = true
			}
			for i, v := range echo_counter {
				if bytes.Compare(v.hash, text.Hash) == 0 && bytes.Compare(v.val.Data, text.Value.Data) == 0 && v.val.Number == text.Value.Number {
					v.count++
					echo_counter[i] = payload{v.count, text.Value, text.Hash}
					key = i
					flag = true
					break
				}

			}

			if flag == false {
				echo_counter[len(echo_counter)] = echo_list[text.Sender]
			}

			if echo_counter[key].count >= (f + 1) {

				ready_hash = echo_counter[key].hash
				ready_val = echo_counter[key].val

			}
			if echo_counter[key].count >= (2*f + 1) {
				ready_sent = true
				Broadcast(ch, Message{id, sid, "READY", echo_counter[key].val, echo_counter[key].hash, nil})

			}
		} else if text.Msgtype == "READY" {
			//fmt.Println("Node", id, "Receiving ready messages...")
			//Checking for redundant Messages
			if ready_list[text.Sender].count >= 1 {
				continue
			}
			//storing  Messages of each Sender
			ready_list[text.Sender] = payload{1, text.Value, text.Hash}

			//Storing (j , m_j) in T_h as T_h[j] = m_j
			T_h = append(T_h, text.Value)

			//f+1 ready Messages and not having sent ready
			if len(ready_list) >= (f+1) && ready_sent == false && len(ready_hash) != 0 && len(ready_val.Data) != 0 {
				ready_sent = true
				Broadcast(ch, Message{id, sid, "READY", ready_val, ready_hash, nil})
			}

			for i := 0; i < f; i += 1 {
				if len(T_h) >= (2*f + 1 + i) {
					if fec == nil {
						fec, err = rs.NewFEC(f+1, n)
						if err != nil {
							panic(err)
						}
					}
					M, err := Rs_dec(n, f+1, T_h, fec)

					if err != nil {
						panic(err)
					}
					if bytes.Compare(hash(M), ready_hash) == 0 {
						if tag == "KEY SET PROPOSAL" {
							ch[id] <- Message{id, sid, "OUTPUT_SET", rs.Share{}, nil, M}
							Output[id] = string(M)
							fmt.Println("\n", "node", id, "Outputed for Key set proposal")

						} else {
							ch[id] <- Message{id, sid, "OUTPUT", rs.Share{}, nil, M}
							Output[id] = string(M)
							fmt.Println("\n", "node", id, "Outputed for ACSS-", sid)

						}

						//just for checking
						wg.Done()
						return
					}
				}
			}

		}

	}

}
