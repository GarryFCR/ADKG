package broadcast

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	rs "github.com/vivint/infectious"
	//rs "github.com/klauspost/reedsolomon"
)

var wg sync.WaitGroup
var Output []string

type fn func([]byte) bool
type Message struct {
	sender  int
	msgtype string
	value   rs.Share //[]byte
	hash    []byte
}

type payload struct {
	count int
	val   rs.Share //[]byte
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

func Rbc(chans []chan Message, msg []byte) []string {

	for i := 0; i < 7; i += 1 {
		wg.Add(1)
		go Run_rbc(7, 2, chans[:], 0, msg, i, predicate)
	}
	wg.Wait()

	for _, c := range chans {
		close(c)
	}
	return Output
}

func predicate(i []byte) bool {
	return true
}

func hash(msg []byte) []byte {
	sum := sha256.Sum256(msg)
	return sum[:]
}

func broadcast(ch []chan Message, msg Message) {

	for _, c := range ch {
		go send(c, msg)
	}
}

func send(ch chan Message, msg Message) {
	ch <- msg
}

func recieve(ch chan Message, x int) Message {
	value := <-ch
	return value
}

func Run_rbc(n int, f int, ch []chan Message, leader int, msg []byte, id int, predicate fn) error {
	fmt.Println("Node -", id, "joined...")

	//Constraints
	if n < 3*f+1 || f < 0 || leader < 0 || leader > n || id < 0 || id > n {
		wg.Done()
		return errors.New("Invalid parameter")
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
	//leader broadcasts
	if leader == id {
		broadcast(ch, Message{id, "PROPOSE", rs.Share{Number: 0, Data: msg}, nil})
	}

	for {

		text := recieve(ch[id], id)

		if text.msgtype == "PROPOSE" {
			fmt.Println("Node", id, "Receiving propose message...")

			if text.sender != leader {
				continue
			} else if predicate(text.value.Data) {
				h := hash(text.value.Data)
				M_i, fec, err = Rs_enc(n, f+1, text.value.Data)
				if err != nil {
					return err
				}
				for i := range ch {
					go send(ch[i], Message{id, "ECHO", M_i[i], h})
				}

			} else {
				wg.Done()
				return errors.New("Invalid value")
			}

		} else if text.msgtype == "ECHO" {
			fmt.Println("Node", id, "Receiving echo messages...")
			//Checking for redundant echo Messages
			if echo_list[text.sender].count >= 1 {
				continue
			}

			//storing echo Messages of each sender
			echo_list[text.sender] = payload{1, text.value, text.hash}

			//Counting the identical echo Messages sent by different senders
			key, flag := 0, false
			if len(echo_counter) == 0 {
				echo_counter[0] = echo_list[text.sender]
				flag = true
			}
			for i, v := range echo_counter {
				if bytes.Compare(v.hash, text.hash) == 0 && bytes.Compare(v.val.Data, text.value.Data) == 0 && v.val.Number == text.value.Number {
					v.count++
					echo_counter[i] = payload{v.count, text.value, text.hash}
					key = i
					flag = true
					break
				}

			}

			if flag == false {
				echo_counter[len(echo_counter)] = echo_list[text.sender]
			}

			if echo_counter[key].count >= (f + 1) {
				ready_hash = echo_counter[key].hash
				ready_val = echo_counter[key].val

			}
			if echo_counter[key].count >= (2*f + 1) {
				ready_sent = true
				broadcast(ch, Message{id, "READY", echo_counter[key].val, echo_counter[key].hash})

			}
		} else if text.msgtype == "READY" {
			fmt.Println("Node", id, "Receiving ready messages...")
			//Checking for redundant Messages
			if ready_list[text.sender].count >= 1 {
				continue
			}
			//storing  Messages of each sender
			ready_list[text.sender] = payload{1, text.value, text.hash}

			//Storing (j , m_j) in T_h as T_h[j] = m_j
			T_h = append(T_h, text.value)

			//f+1 ready Messages and not having sent ready
			if len(ready_list) >= (f+1) && ready_sent == false && len(ready_hash) != 0 && len(ready_val.Data) != 0 {
				ready_sent = true
				broadcast(ch, Message{id, "READY", ready_val, ready_hash})
			}

			for i := 0; i < f; i += 1 {
				if len(T_h) >= (2*f + 1 + i) {
					M, err := Rs_dec(n, f+1, T_h, fec)
					if err != nil {
						return err
					}
					if bytes.Compare(hash(M), ready_hash) == 0 {
						fmt.Println("\n", id, "Outputed :", string(M))
						//just for checking
						Output = append(Output, string(M))
						wg.Done()
						return nil
					}
				}
			}

		}

	}

}

/*
rs for erasure coding
func Rs_enc(msg []byte, n int, parity int) ([][]byte, error) {

	if n < parity {
		return nil, errors.New("Invalid parity or number of nodes")
	}

	enc, err := rs.New(n, parity)
	if err != nil {
		panic(err)
	}
	shards, err := enc.Split(msg)

	// Encode the parity set
	err = enc.Encode(shards)
	if err != nil {
		panic(err)
	}

	// Verify the parity set
	ok, err := enc.Verify(shards)
	if ok && err == nil {
		//fmt.Println("Encoded")
	}

	return shards, nil
}

//TODO : Correct errors
func Rs_dec(T [][]byte, parity int, n int) []byte {

	enc, err := rs.New(n, parity)
	if err != nil {
		panic(err)
	}
	// Reconstruct the shards
	_ = enc.Reconstruct(T)
	//fmt.Println(err, T)

	// Verify the data set
	ok, err := enc.Verify(T)
	if ok {
		var b bytes.Buffer
		err := enc.Join(&b, T, n)
		msg := b.Bytes()
		if err == nil {
			for {
				if msg[len(msg)-1] != 0 {
					return msg
				}
				msg = msg[:(len(msg) - 1)]
			}

		} else {
			panic(err)
		}
	} else {
		panic(err)
	}

}*/
