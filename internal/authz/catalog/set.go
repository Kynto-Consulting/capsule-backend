package catalog

import (
	"encoding/hex"
	"math/bits"
	"strings"
)

// MaxPerms is the capacity of a Set.
const MaxPerms = 128

// Set is a set of catalog permissions as a 128-bit bitset. It is a small value type: copy it freely,
// compare it with ==, and none of its operations allocates except the ones that return slices or strings.
// The bit of a permission is catalog.Bit(id).
type Set struct{ w [2]uint64 }

// NewSet returns the set of the given ids. Ids that are not in the catalog are ignored (fail closed:
// an unknown permission grants nothing).
func NewSet(ids ...string) Set {
	s, _ := ParseSet(ids)
	return s
}

// ParseSet builds a Set and returns the ids it did not recognise.
func ParseSet(ids []string) (Set, []string) {
	var s Set
	var unknown []string
	for _, id := range ids {
		if b, ok := index[id]; ok {
			s = s.addBit(b)
		} else {
			unknown = append(unknown, id)
		}
	}
	return s, unknown
}

// Full is the set of every catalog permission.
func Full() Set {
	var s Set
	for i := range perms {
		s = s.addBit(i)
	}
	return s
}

func (s Set) addBit(b int) Set {
	s.w[b>>6] |= 1 << (uint(b) & 63)
	return s
}

// Add returns s plus id (unknown ids are ignored).
func (s Set) Add(id string) Set {
	if b, ok := index[id]; ok {
		return s.addBit(b)
	}
	return s
}

// Has reports whether id is in s. Unknown ids are never in a set.
func (s Set) Has(id string) bool {
	b, ok := index[id]
	return ok && s.HasBit(b)
}

// HasBit is Has by bit position (the allocation-free hot path).
func (s Set) HasBit(b int) bool {
	if b < 0 || b >= MaxPerms {
		return false
	}
	return s.w[b>>6]&(1<<(uint(b)&63)) != 0
}

// Union returns s | o.
func (s Set) Union(o Set) Set { return Set{[2]uint64{s.w[0] | o.w[0], s.w[1] | o.w[1]}} }

// Intersect returns s & o.
func (s Set) Intersect(o Set) Set { return Set{[2]uint64{s.w[0] & o.w[0], s.w[1] & o.w[1]}} }

// Minus returns s without the members of o.
func (s Set) Minus(o Set) Set { return Set{[2]uint64{s.w[0] &^ o.w[0], s.w[1] &^ o.w[1]}} }

// ContainsAll reports whether every member of o is in s. The empty set is contained in everything.
func (s Set) ContainsAll(o Set) bool { return o.Minus(s).IsEmpty() }

// IsEmpty reports whether the set has no members.
func (s Set) IsEmpty() bool { return s.w[0]|s.w[1] == 0 }

// Len is the number of members.
func (s Set) Len() int { return bits.OnesCount64(s.w[0]) + bits.OnesCount64(s.w[1]) }

// IDs lists the members in catalog (bit) order.
func (s Set) IDs() []string {
	out := make([]string, 0, s.Len())
	for i := range perms {
		if s.HasBit(i) {
			out = append(out, perms[i].ID)
		}
	}
	return out
}

// Hex is the 32-character big-endian hexadecimal mask (bit 0 is the least significant bit of the last
// digit). It is the "mask" format of GET /me/permissions.
func (s Set) Hex() string {
	var b [16]byte
	for i := 0; i < 8; i++ {
		b[7-i] = byte(s.w[1] >> (8 * uint(i)))
		b[15-i] = byte(s.w[0] >> (8 * uint(i)))
	}
	return hex.EncodeToString(b[:])
}

// SetFromHex parses the output of Hex. Bits beyond the catalog are cleared (unknown permissions grant nothing).
func SetFromHex(h string) (Set, bool) {
	h = strings.TrimPrefix(strings.ToLower(h), "0x")
	if len(h) == 0 || len(h) > 32 {
		return Set{}, false
	}
	h = strings.Repeat("0", 32-len(h)) + h
	raw, err := hex.DecodeString(h)
	if err != nil {
		return Set{}, false
	}
	var s Set
	for i := 0; i < 8; i++ {
		s.w[1] |= uint64(raw[7-i]) << (8 * uint(i))
		s.w[0] |= uint64(raw[15-i]) << (8 * uint(i))
	}
	return s.Intersect(Full()), true
}
