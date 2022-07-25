package aba

import (
	"errors"
	"fmt"
	"strconv"
	"sync"

	br "github.com/GarryFCR/ADKG/broadcast"
	"github.com/coinbase/kryptology/pkg/core/curves"
	feld "github.com/coinbase/kryptology/pkg/sharing"
	rs "github.com/vivint/infectious"
)

var bin1_mutex, bin2_mutex, estsent1_mutex, estsent2_mutex, est1val_mutex, est2val_mutex, aux1_mutex, aux2_mutex, auxset_mutex sync.RWMutex

func get_bin(maptype string, r int, bin map[int][]int) []int {
	if maptype == "BIN1" {
		bin1_mutex.RLock()
		defer bin1_mutex.RUnlock()
	} else {
		bin2_mutex.RLock()
		defer bin2_mutex.RUnlock()
	}

	return bin[r]
}

func set_bin(maptype string, r, nodeid int, bin map[int][]int) {
	if maptype == "BIN1" {
		bin1_mutex.Lock()
		defer bin1_mutex.Unlock()
	} else {
		bin2_mutex.Lock()
		defer bin2_mutex.Unlock()
	}

	bin[r] = append(bin[r], nodeid)
}

func get_estsent(maptype string, r, est int, est_sent map[int]map[int]bool) bool {

	if maptype == "EST1" {
		estsent1_mutex.RLock()
		defer estsent1_mutex.RUnlock()
	} else {
		estsent2_mutex.RLock()
		defer estsent2_mutex.RUnlock()
	}

	return est_sent[r][est]
}

func set_estsent(maptype string, r, est int, est_sent map[int]map[int]bool) {

	if maptype == "EST1" {
		estsent1_mutex.Lock()
		defer estsent1_mutex.Unlock()
	} else {
		estsent2_mutex.Lock()
		defer estsent2_mutex.Unlock()
	}
	if est_sent[r] == nil {
		est_sent[r] = map[int]bool{}

	}
	est_sent[r][est] = true

}

func get(maptype string, r, v int, mapping map[int]map[int][]int) []int {
	if maptype == "ESTVAL1" {
		est1val_mutex.RLock()
		defer est1val_mutex.RUnlock()
	} else if maptype == "ESTVAL2" {
		est2val_mutex.RLock()
		defer est2val_mutex.RUnlock()
	} else if maptype == "AUX1" {
		aux1_mutex.RLock()
		defer aux1_mutex.RUnlock()
	} else if maptype == "AUX2" {
		aux2_mutex.RLock()
		defer aux2_mutex.RUnlock()
	} else {
		auxset_mutex.RLock()
		defer auxset_mutex.RUnlock()
	}

	return mapping[r][v]
}

func set(maptype string, r, v, nodeid int, mapping map[int]map[int][]int) {
	if maptype == "ESTVAL1" {
		est1val_mutex.Lock()
		defer est1val_mutex.Unlock()
	} else if maptype == "ESTVAL2" {
		est2val_mutex.Lock()
		defer est2val_mutex.Unlock()
	} else if maptype == "AUX1" {
		aux1_mutex.Lock()
		defer aux1_mutex.Unlock()
	} else if maptype == "AUX2" {
		aux2_mutex.Lock()
		defer aux2_mutex.Unlock()
	} else {
		auxset_mutex.Lock()
		defer auxset_mutex.Unlock()
	}

	if mapping[r] == nil {
		mapping[r] = map[int][]int{}
	}

	mapping[r][v] = append(mapping[r][v], nodeid)

}

func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func Broadcast(ch []chan br.Message, msg br.Message) {
	var wg sync.WaitGroup
	for _, c := range ch {
		wg.Add(1)
		go func(x chan br.Message) {
			x <- msg
			defer wg.Done()
		}(c)

	}
	wg.Wait()
	return
}

func Propose(
	vote, id, n, k int, //proposal,node id,number of parties,threshold numbers,aba number
	chans []chan br.Message,
	curve *curves.Curve,
	Sid int,
	shares []*feld.ShamirShare,
	T_j []int,
	commitment map[int][]curves.Point) (int, error) {

	if n < 3*k-2 {
		panic(errors.New("Invalid parameter"))
	}
	bin_values1 := make(map[int][]int) //can have only  1 and/or 0
	bin_values2 := make(map[int][]int) //can have only  1 and/or 0 and/or 2
	est_values1 := make(map[int]map[int][]int)
	est_values2 := make(map[int]map[int][]int)
	est_sent1 := make(map[int]map[int]bool)
	est_sent2 := make(map[int]map[int]bool)
	aux_values1 := make(map[int]map[int][]int) // r,v -> set of senders , v = 0 or 1
	aux_values2 := make(map[int]map[int][]int) // r,v -> set of senders , v = 0 or 1 or 2
	auxset_values := make(map[int]map[int][]int)

	if vote != 1 && vote != 0 {
		return 2, errors.New("Invalid input")
	}

	//listen to recieving channel
	go recieve(id, k, chans, bin_values1, bin_values2, est_values1, est_values2, est_sent1, est_sent2, aux_values1, aux_values2, auxset_values)

	est1 := vote
	r := 0
	view1 := make([]int, 0)
	values2 := make([]int, 0)

	for {

		r = +1
		output := make([]byte, 0)
		//bv broadcast1

		if get_estsent("EST1", r, est1, est_sent1) == false {

			set_estsent("EST1", r, est1, est_sent1)
			output = []byte{byte(est1), byte(r)} //estimate || round no
			Broadcast(chans, br.Message{Sender: id, Msgtype: "EST1", Value: rs.Share{}, Hash: nil, Output: output})
		}

		for {
			if len(get_bin("BIN1", r, bin_values1)) > 0 {
				break
			}
		}
		bin_array := get_bin("BIN1", r, bin_values1)
		w := bin_array[0]

		//sbv broadcast1

		output = []byte{byte(w), byte(r)}
		Broadcast(chans, br.Message{Sender: id, Msgtype: "AUX1", Value: rs.Share{}, Hash: nil, Output: output})

		for {
			bin_array = get_bin("BIN1", r, bin_values1)
			len0 := len(get("AUX1", r, 0, aux_values1))
			len1 := len(get("AUX1", r, 1, aux_values1))
			if contains(bin_array, 0) && len0 >= (n-k-1) {
				view1 = append(view1, 0)

				break
			} else if contains(bin_array, 1) && len1 >= (n-k-1) {
				view1 = append(view1, 1)

				break
			} else if (len0+len1) >= (n-k-1) && contains(bin_array, 0) && contains(bin_array, 1) {
				view1 = append(view1, 0, 1)
				break
			}
		}

		//auxset
		var est2 int
		v := 0
		if len(view1) == 1 && view1[0] == 1 {
			v = 1
		} else if len(view1) == 2 {
			v = 2
		}

		output = []byte{byte(v), byte(r)}
		Broadcast(chans, br.Message{Sender: id, Msgtype: "AUXSET", Value: rs.Share{}, Hash: nil, Output: output})

		for {
			bin_array = get_bin("BIN1", r, bin_values1)
			len0 := len(get("AUXSET", r, 0, auxset_values))
			len1 := len(get("AUXSET", r, 1, auxset_values))
			if contains(bin_array, 1) && len1 >= (n-k-1) {
				est2 = 1
				break
			} else if contains(bin_array, 0) && len0 >= (n-k-1) {
				est2 = 0
				break

			} else if (len0+len1+len(get("AUXSET", r, 2, auxset_values))) >= (n-k-1) && contains(bin_array, 0) && contains(bin_array, 1) {
				est2 = 2
				break
			}
		}

		//bv broadcast2
		if get_estsent("EST2", r, est2, est_sent2) == false {
			set_estsent("EST2", r, est2, est_sent2)
			output = []byte{byte(est2), byte(r)}
			Broadcast(chans, br.Message{Sender: id, Msgtype: "EST2", Value: rs.Share{}, Hash: nil, Output: output})

		}

		for {
			if len(get_bin("BIN2", r, bin_values2)) > 0 {
				break
			}
		}

		bin_array = get_bin("BIN2", r, bin_values2)
		w = bin_array[0]
		//sbv broadcast2
		output = []byte{byte(w), byte(r)}
		Broadcast(chans, br.Message{Sender: id, Msgtype: "AUX2", Value: rs.Share{}, Hash: nil, Output: output})

		//lemma 6
		for {
			bin_array = get_bin("BIN2", r, bin_values2)
			len0 := len(get("AUX2", r, 0, aux_values2))
			len1 := len(get("AUX2", r, 1, aux_values2))
			len2 := len(get("AUX2", r, 2, aux_values2))

			if contains(bin_array, 0) && len0 >= (n-k-1) {
				values2 = append(values2, 0)
				break
			} else if contains(bin_array, 1) && len1 >= (n-k-1) {
				values2 = append(values2, 1)
				break
			} else if contains(bin_array, 2) && len2 >= (n-k-1) {
				values2 = append(values2, 2)
				break
			} else if (len0+len2) >= (n-k-1) && contains(bin_array, 0) && contains(bin_array, 2) {
				values2 = append(values2, 0, 2)
				break
			} else if (len1+len2) >= (n-k-1) && contains(bin_array, 1) && contains(bin_array, 2) {
				values2 = append(values2, 1, 2)
				break
			}
		}

		if len(values2) == 1 {
			if values2[0] != 2 {
				return values2[0], nil
			} else if values2[0] == 2 {
				// call coin
				fmt.Println("Calling coin")
				coin_id := strconv.Itoa(Sid) + strconv.Itoa(r)
				res := Coin(k, id, coin_id, curve, shares, T_j, commitment, chans)
				if res == true {
					return 1, nil
				}
				return 0, nil

			}
		} else if len(values2) == 2 {
			est1 = values2[0]
		}

	}

}

func recieve(
	id, k int,
	chans []chan br.Message,
	bin_values1 map[int][]int,
	bin_values2 map[int][]int, //can have only  1 and/or 0 and/or 2
	est_values1 map[int]map[int][]int,
	est_values2 map[int]map[int][]int,
	est_sent1 map[int]map[int]bool,
	est_sent2 map[int]map[int]bool,
	aux_values1 map[int]map[int][]int, // r,v -> set of senders , v = 0 or 1
	aux_values2 map[int]map[int][]int, // r,v -> set of senders , v = 0 or 1 or 2
	auxset_values map[int]map[int][]int) {

	for {
		select {
		case x, ok := <-chans[id]:
			if ok {
				//recieving bv broadcast1
				if x.Msgtype == "EST1" {
					v, r := int(x.Output[0]), int(x.Output[1])
					estval_array := get("ESTVAL1", r, v, est_values1)
					if contains(estval_array, x.Sender) || v < 0 || v > 2 {
						continue
					}
					set("ESTVAL1", r, v, x.Sender, est_values1)
					estval_array = get("ESTVAL1", r, v, est_values1)

					if len(estval_array) >= k && get_estsent("EST1", r, v, est_sent1) == false {
						set_estsent("EST1", r, v, est_sent1)
						output := []byte{byte(v), byte(r)}
						Broadcast(chans, br.Message{Sender: id, Msgtype: "EST1", Value: rs.Share{}, Hash: nil, Output: output})

					}

					if len(estval_array) >= (2*k-1) && contains(get_bin("BIN1", r, bin_values1), v) == false {
						set_bin("BIN1", r, v, bin_values1)

					}

				} else if x.Msgtype == "AUX1" {
					v, r := int(x.Output[0]), int(x.Output[1])

					if contains(get("AUX1", r, v, aux_values1), x.Sender) && v != 0 && v != 1 {
						continue
					}
					set("AUX1", r, v, x.Sender, aux_values1)

				} else if x.Msgtype == "AUXSET" {
					v, r := int(x.Output[0]), int(x.Output[1])

					if contains(get("AUXSET", r, v, auxset_values), x.Sender) && v < 0 && v > 2 {
						continue
					}
					set("AUXSET", r, v, x.Sender, auxset_values)

				} else if x.Msgtype == "EST2" {
					v, r := int(x.Output[0]), int(x.Output[1])

					estval_array := get("ESTVAL2", r, v, est_values2)
					if contains(estval_array, x.Sender) || v < 0 || v > 2 {
						continue
					}
					set("ESTVAL2", r, v, x.Sender, est_values2)

					if len(estval_array) >= k && get_estsent("EST2", r, v, est_sent2) == false {
						set_estsent("EST2", r, v, est_sent2)
						output := []byte{byte(v), byte(r)}
						Broadcast(chans, br.Message{Sender: id, Msgtype: "EST2", Value: rs.Share{}, Hash: nil, Output: output})

					}

					if len(estval_array) >= (2*k-1) && contains(get_bin("BIN2", r, bin_values2), v) == false {
						set_bin("BIN2", r, v, bin_values2)

					}

				} else if x.Msgtype == "AUX2" {
					v, r := int(x.Output[0]), int(x.Output[1])

					if contains(get("AUX2", r, v, aux_values2), x.Sender) && v < 0 && v > 2 {
						continue
					}

					set("AUX2", r, v, x.Sender, aux_values2)

				}

			}
		default:
			continue
		}

	}

}
