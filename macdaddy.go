package macdaddy

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math/rand"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

var errAuthFailed = errors.New("macdaddy: message authentication failed")

const (
	epochSize = 4
	nonceSize = chacha20poly1305.NonceSize

	nonceOffset   = 0 + epochSize
	messageOffset = nonceOffset + nonceSize
)

// MAC has the ability to encrypt and decrypt (short) messages as long as they
// share the same key and the same epoch.
type MAC struct {
	parent cipher.AEAD
	epoch  []byte
	random *rand.Rand

	mu sync.Mutex
}

// New builds a new MAC using a 256-bit/32 byte encryption key, a numeric epoch
// and numeric pseudo-random seed
func New(key []byte, epoch uint32, seed int64) (*MAC, error) {
	parent, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	epochData := make([]byte, epochSize)
	binary.LittleEndian.PutUint32(epochData, epoch)

	return &MAC{
		parent: parent,
		epoch:  epochData,
		random: rand.New(rand.NewSource(seed)),
	}, nil
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext.
func (m *MAC) Overhead() int { return m.parent.Overhead() + epochSize + nonceSize }

// Epoch returns the current epoch
func (m *MAC) Epoch() uint32 { return binary.LittleEndian.Uint32(m.epoch) }

// Encrypt encrypts src and appends to dst, returning the
// resulting byte slice
func (m *MAC) Encrypt(dst, src []byte) []byte {
	dst = append(dst, m.epoch...)
	dst = append(dst, make([]byte, chacha20poly1305.NonceSize)...)
	m.mu.Lock()
	m.random.Read(dst[nonceOffset:messageOffset])
	m.mu.Unlock()

	return m.parent.Seal(dst, dst[nonceOffset:messageOffset], src, nil)
}

// Decrypt decrypts src and appends to dst, returning the
// resulting byte slice or an error if the input cannot be
// authenticated.
func (m *MAC) Decrypt(dst, src []byte) ([]byte, error) {
	if len(src) < m.Overhead() {
		return dst, errAuthFailed
	}

	if !bytes.Equal(src[:nonceOffset], m.epoch) {
		return dst, errAuthFailed
	}

	dst, err := m.parent.Open(dst, src[nonceOffset:messageOffset], src[messageOffset:], nil)
	if err != nil {
		return dst, errAuthFailed
	}
	return dst, nil
}
