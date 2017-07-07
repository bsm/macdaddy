package macdaddy

import (
	"bytes"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("MAC", func() {
	var key = []byte("THISisOURverySECRET32byteTESTkey")
	var src = "plaintext"

	It("should fail to init on bad keys", func() {
		_, err := New([]byte("too short"), 1, 0)
		Expect(err).To(MatchError("chacha20poly1305: bad key length"))
	})

	It("should have a epoch", func() {
		mac, err := New(key, 321, 100)
		Expect(err).NotTo(HaveOccurred())
		Expect(mac.Epoch()).To(Equal(uint32(321)))
	})

	It("should declare overhead", func() {
		mac, err := New(key, 1, 100)
		Expect(err).NotTo(HaveOccurred())
		Expect(mac.Overhead()).To(Equal(32))
	})

	It("should encrypt", func() {
		mac, err := New(key, 1, 100)
		Expect(err).NotTo(HaveOccurred())
		Expect(mac.Encrypt(nil, nil)).To(HaveLen(32))

		m1 := mac.Encrypt(nil, []byte("plaintext"))
		m2 := mac.Encrypt(nil, []byte("plaintext"))
		Expect(m1).To(HaveLen(41))
		Expect(m2).To(HaveLen(41))
		Expect(m1).NotTo(Equal(m2))
	})

	It("should open", func() {
		mac, err := New(key, 1, 100)
		Expect(err).NotTo(HaveOccurred())

		m1 := mac.Encrypt(nil, []byte(src))
		m2 := mac.Encrypt(nil, []byte(src))
		Expect(m1).NotTo(Equal(m2))

		p1, err := mac.Decrypt(nil, m1)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(p1)).To(Equal(src))

		p2, err := mac.Decrypt(nil, m2)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(p2)).To(Equal(src))
	})

	It("should encrypt/open independently of seeds", func() {
		mac1, err := New(key, 1, 100)
		Expect(err).NotTo(HaveOccurred())

		mac2, err := New(key, 1, 200)
		Expect(err).NotTo(HaveOccurred())

		m1 := mac1.Encrypt(nil, []byte(src))
		m2 := mac2.Encrypt(nil, []byte(src))
		Expect(m1).NotTo(Equal(m2))

		p1, err := mac2.Decrypt(nil, m1)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(p1)).To(Equal(src))

		p2, err := mac1.Decrypt(nil, m2)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(p2)).To(Equal(src))
	})

	It("should require consistent keys", func() {
		mac1, err := New(key, 1, 100)
		Expect(err).NotTo(HaveOccurred())

		mac2, err := New(bytes.ToUpper(key), 1, 200)
		Expect(err).NotTo(HaveOccurred())

		m1 := mac1.Encrypt(nil, []byte(src))
		m2 := mac2.Encrypt(nil, []byte(src))
		Expect(m1).NotTo(Equal(m2))

		_, err = mac2.Decrypt(nil, m1)
		Expect(err).To(Equal(ErrBadToken))
		_, err = mac1.Decrypt(nil, m2)
		Expect(err).To(Equal(ErrBadToken))
	})

	It("should require consistent epochs", func() {
		mac1, err := New(key, 1, 100)
		Expect(err).NotTo(HaveOccurred())

		mac2, err := New(key, 2, 200)
		Expect(err).NotTo(HaveOccurred())

		m1 := mac1.Encrypt(nil, []byte(src))
		m2 := mac2.Encrypt(nil, []byte(src))
		Expect(m1).NotTo(Equal(m2))

		_, err = mac2.Decrypt(nil, m1)
		Expect(err).To(Equal(ErrUnknownEpoch))
		_, err = mac1.Decrypt(nil, m2)
		Expect(err).To(Equal(ErrUnknownEpoch))
	})

})

// ------------------------------------------------------------------------

func TestSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "macdaddy")
}

func BenchmarkMAC_Encrypt_64(b *testing.B) { benchmarkMACEncrypt(b, 64) }
func BenchmarkMAC_Encrypt_1k(b *testing.B) { benchmarkMACEncrypt(b, 1024) }
func BenchmarkMAC_Encrypt_1M(b *testing.B) { benchmarkMACEncrypt(b, 1024*024) }

func BenchmarkMAC_Decrypt_64(b *testing.B) { benchmarkMACDecrypt(b, 64) }
func BenchmarkMAC_Decrypt_1k(b *testing.B) { benchmarkMACDecrypt(b, 1024) }
func BenchmarkMAC_Decrypt_1M(b *testing.B) { benchmarkMACDecrypt(b, 1024*1024) }

func benchmarkMACEncrypt(b *testing.B, n int) {
	key := bytes.Repeat([]byte{'x'}, 32)
	msg := bytes.Repeat([]byte{'x'}, n)
	mac, err := New(key, 0, 0)
	if err != nil {
		b.Fatal(err)
	}

	var dst []byte
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dst = mac.Encrypt(dst[:0], msg)
	}
}

func benchmarkMACDecrypt(b *testing.B, n int) {
	key := bytes.Repeat([]byte{'x'}, 32)
	mac, err := New(key, 0, 0)
	if err != nil {
		b.Fatal(err)
	}
	msg := mac.Encrypt(nil, bytes.Repeat([]byte{'x'}, n))

	var dst []byte
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dst, err = mac.Decrypt(dst[:0], msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}
