package macdaddy_test

import (
	"fmt"
	"time"

	"github.com/bsm/macdaddy"
)

func ExampleMAC() {
	// Secrets must be 32 bytes long.
	secret := []byte("ThisMustNotBeSharedWithStrangers")

	// Epochs are numeric and must match.
	epoch := uint32(20170308)

	// Generate a MAC, using a secret, an epoch and a random seed.
	mac1, err := macdaddy.New(secret, epoch, time.Now().Unix())
	if err != nil {
		panic(err)
	}

	// Encrypt a message
	encrypted := mac1.Encrypt(nil, []byte("plaintext"))

	// Decrypt the message again
	plain1, err := mac1.Decrypt(nil, encrypted)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%q\n", plain1)

	// To decrypt each other's messages, MACs must share
	// the secret and the epoch, but not the seed
	mac2, err := macdaddy.New(secret, epoch, 451)
	if err != nil {
		panic(err)
	}
	plain2, err := mac2.Decrypt(nil, encrypted)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%q\n", plain2)

	// Output:
	// "plaintext"
	// "plaintext"
}

func ExampleRing() {
	const seed = 1234567890

	// This is our latest/primary MAC
	latest, err := macdaddy.New([]byte("ThisIsOurVeryLatestSecretKey2017"), 2017, seed)
	if err != nil {
		panic(err)
	}

	// This is a MAC we have used previously
	previous, err := macdaddy.New([]byte("ThisIsAKeyWeUsedPreviouslyIn2016"), 2016, seed)
	if err != nil {
		panic(err)
	}

	// This is another legacy MAC we have used before
	legacy, err := macdaddy.New([]byte("ThisOneIsLegacyWeStillKeepAround"), 2010, seed)
	if err != nil {
		panic(err)
	}

	// Create a new ring, register legacy MACc
	ring := macdaddy.NewRing(latest)
	ring.Register(previous)
	ring.Register(legacy)

	// Encrypt a new message
	encrypted := ring.Encrypt(nil, []byte("I was encrypted with the latest key"))

	// Decrypt the message
	plain, err := ring.Decrypt(nil, encrypted)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%q\n", plain)

	// Now, decrypt a message encrypted with a previous MACs
	oldmsg := previous.Encrypt(nil, []byte("I may from a different epoch but still decryptable"))
	plain, err = ring.Decrypt(plain[:0], oldmsg)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%q\n", plain)

	// Output:
	// "I was encrypted with the latest key"
	// "I may from a different epoch but still decryptable"
}
