package Broadcast

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	feld "github.com/coinbase/kryptology/pkg/sharing"
	rs "github.com/vivint/infectious"

	"gitlab.com/elktree/ecc"
)

var wg sync.WaitGroup
var wg1 sync.WaitGroup

var Output []string

//type fn func([]byte) bool
type fn func(
	sk *ecc.PrivateKey,
	verifier *feld.FeldmanVerifier,
	c []byte,
	k, i int,
	chans []chan Message) bool

type Message struct {
	Sender  int
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

func Rbc(priv []*ecc.PrivateKey,
	verifier *feld.FeldmanVerifier,
	chans []chan Message,
	msg []byte,
	n, f, leader int, //here f is the number of faulty parties
	predicate fn) []string {

	for i := 0; i < n; i += 1 {
		wg.Add(1)
		go Run_rbc(n, f, chans[:], leader, msg, i, predicate, priv[i], verifier)
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
func recieve(ch chan Message, x int) Message {
	value := <-ch
	return value
}

func Run_rbc(
	n int,
	f int,
	ch []chan Message,
	leader int,
	msg []byte,
	id int,
	predicate fn,
	sk *ecc.PrivateKey,
	verifier *feld.FeldmanVerifier) {

	fmt.Println("Node -", id, "joined...")

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
		Broadcast(ch, Message{id, "PROPOSE", rs.Share{Number: 0, Data: msg}, nil, nil})

	}

	for {

		text := recieve(ch[id], id)
		if text.Msgtype == "PROPOSE" {
			fmt.Println("Node", id, "Receiving propose message...")

			if text.Sender != leader {
				continue
			} else if predicate(sk, verifier, msg, f+1, id, ch) {
				h := hash(text.Value.Data)

				M_i, fec, err = Rs_enc(n, f+1, text.Value.Data)

				if err != nil {
					panic(err)
				}
				for i := range ch {
					go send(ch[i], Message{id, "ECHO", M_i[i], h, nil})
				}

			} else {
				key, _ := sk.Marshal()
				Broadcast(ch, Message{id, "IMPLICATE", rs.Share{}, nil, key})
				fmt.Println("Invalid value by", id)
				fmt.Println("Sending implicate message...")
				time.Sleep(3 * time.Second)

				wg.Done()
				return
			}

		} else if text.Msgtype == "ECHO" {
			fmt.Println("Node", id, "Receiving echo messages...")
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
				Broadcast(ch, Message{id, "READY", echo_counter[key].val, echo_counter[key].hash, nil})

			}
		} else if text.Msgtype == "READY" {
			fmt.Println("Node", id, "Receiving ready messages...")
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
				Broadcast(ch, Message{id, "READY", ready_val, ready_hash, nil})
			}

			for i := 0; i < f; i += 1 {
				if len(T_h) >= (2*f + 1 + i) {
					M, err := Rs_dec(n, f+1, T_h, fec)
					if err != nil {
						fmt.Println("here:", id)
						panic(err)
					}
					if bytes.Compare(hash(M), ready_hash) == 0 {
						go send(ch[id], Message{id, "OUTPUT", rs.Share{}, nil, M})
						fmt.Println("\n", "node", id, "Outputed ")
						//just for checking
						Output = append(Output, string(M))
						wg.Done()
						return
					}
				}
			}

		}

	}

}
