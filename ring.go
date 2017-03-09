package macdaddy

import "encoding/binary"

// Ring represents a MAC ring capable of opening
// messages encrypted by MACs from various epochs.
//
// The goal of a ring is to allow keys to be rotated
// while retaining backwards compatibility for keys
// used in previous epochs.
type Ring struct {
	primary  *MAC
	registry map[uint32]*MAC
}

// NewRing creates a suite with a primary MAC,
// which is used for all encoding operations.
func NewRing(primary *MAC) *Ring {
	return &Ring{
		primary:  primary,
		registry: map[uint32]*MAC{primary.Epoch(): primary},
	}
}

// Register registers an additional MAC. Please note that
// registraion is based on the epoch. MACs with clashing epoch values
// may override other, previously registered ones.
func (r *Ring) Register(m *MAC) {
	r.registry[m.Epoch()] = m
}

// Encrypt uses the primary MAC to encrypt a message
func (r *Ring) Encrypt(dst, src []byte) []byte {
	return r.primary.Encrypt(dst, src)
}

// Decrypt decrypts a message by using the correct
// MAC from the determined message term
func (r *Ring) Decrypt(dst, src []byte) ([]byte, error) {
	if len(src) < epochSize {
		return dst, errAuthFailed
	}

	term := binary.LittleEndian.Uint32(src)
	mac, ok := r.registry[term]
	if !ok {
		return dst, errAuthFailed
	}

	return mac.Decrypt(dst, src)
}
