/*
 * Copyright 2024 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package workload

import (
	"hash/fnv"
	"math"
)

var (
	hash = fnv.New32a()
)

const tombstoneMarker = "\x00"

// HashName converts a string to a uint32 integer as the key of bpf map
type HashName struct {
	numToStr map[uint32]string
	// records its tombstone number given a string
	tombstones map[string]uint32
}

func NewHashName() *HashName {
	con := &HashName{}
	con.numToStr = make(map[uint32]string)
	con.tombstones = make(map[string]uint32)
	return con
}

func (h *HashName) StrToNum(str string) uint32 {
	var num uint32

	if num, exists := h.tombstones[str]; exists {
		h.numToStr[num] = str
		delete(h.tombstones, str)
		return num
	}

	hash.Reset()
	hash.Write([]byte(str))

	// Using linear probing to solve hash conflicts
	for num = hash.Sum32(); num < math.MaxUint32; num++ {
		// We will keep searching until we find an unused slot
		// We won't use the slot with tombstone marker
		if h.numToStr[num] == "" {
			h.numToStr[num] = str
			break
		} else if h.numToStr[num] == str {
			break
		}
	}

	return num
}

func (h *HashName) NumToStr(num uint32) string {
	str := h.numToStr[num]
	if str != tombstoneMarker {
		return str
	}
	return ""
}

func (h *HashName) Delete(str string) {
	// instead of directly deleting, we put a tombstone here
	num := h.StrToNum(str)
	h.numToStr[num] = tombstoneMarker
	h.tombstones[str] = num
}
