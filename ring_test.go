package macdaddy

import (
	"bytes"

	. "github.com/bsm/ginkgo/v2"
	. "github.com/bsm/gomega"
)

var _ = Describe("Ring", func() {
	var subject *Ring
	var key = []byte("THISisOURverySECRET32byteTESTkey")
	var plain = bytes.Repeat([]byte{'x'}, 64)
	var mac6, mac7 *MAC

	BeforeEach(func() {
		var err error

		mac7, err = New(key, 7, 0)
		Expect(err).NotTo(HaveOccurred())

		mac6, err = New(key, 6, 0)
		Expect(err).NotTo(HaveOccurred())

		subject = NewRing(mac7)
		subject.Register(mac6)
	})

	It("should encrypt using primary mac", func() {
		msg := subject.Encrypt(nil, plain)

		_, err := mac7.Decrypt(nil, msg)
		Expect(err).NotTo(HaveOccurred())
		_, err = mac6.Decrypt(nil, msg)
		Expect(err).To(Equal(ErrUnknownEpoch))
	})

	It("should decrypt using registered mac", func() {
		_, err := subject.Decrypt(nil, mac7.Encrypt(nil, plain))
		Expect(err).NotTo(HaveOccurred())
		_, err = subject.Decrypt(nil, mac6.Encrypt(nil, plain))
		Expect(err).NotTo(HaveOccurred())
	})

	It("should fail to decrypt invalid messages", func() {
		_, err := subject.Decrypt(nil, []byte("a"))
		Expect(err).To(Equal(ErrBadToken))
	})

	It("should fail to decrypt messages from bad terms", func() {
		mac3, err := New(key, 3, 0)
		Expect(err).NotTo(HaveOccurred())

		_, err = subject.Decrypt(nil, mac3.Encrypt(nil, plain))
		Expect(err).To(Equal(ErrUnknownEpoch))
	})

	It("should fail to decrypt messages from non-matching MACs", func() {
		mac6b, err := New(bytes.ToUpper(key), 6, 0)
		Expect(err).NotTo(HaveOccurred())

		_, err = subject.Decrypt(nil, mac6b.Encrypt(nil, plain))
		Expect(err).To(Equal(ErrBadToken))
	})

})
