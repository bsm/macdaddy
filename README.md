# MAC Daddy

[![GoDoc](https://godoc.org/github.com/bsm/macdaddy?status.svg)](https://godoc.org/github.com/bsm/macdaddy)
[![Build Status](https://travis-ci.org/bsm/macdaddy.svg?branch=master)](https://travis-ci.org/bsm/macdaddy)
[![Go Report Card](https://goreportcard.com/badge/github.com/bsm/macdaddy)](https://goreportcard.com/report/github.com/bsm/macdaddy)

MAC Daddy is a [Go](https://golang.org) library for generating encrypted messages and verifying their authenticity using the [Poly1305](https://en.wikipedia.org/wiki/Poly1305) [message authentication code](https://en.wikipedia.org/wiki/Message_authentication_code) with a [ChaCha20](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) cipher.

## Documentation

For documentation and examples, please see https://godoc.org/github.com/bsm/macdaddy.

## Install

```
go get -u github.com/bsm/macdaddy
```

## Basic Usage

```go
package main

import (
	"fmt"

	"github.com/bsm/macdaddy"
)

func main() {
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

}
```

Output:

```go
"plaintext"
"plaintext"
```

## Ring Usage

To simplify key rotation MAC Daddy comes with a Ring which can use a variety
of registered MACs. It always uses a primary MAC for encryption while capable
of decrypting messages created by MACs from previous epochs.

```go
package main

import (
	"fmt"

	"github.com/bsm/macdaddy"
)

func main() {
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

}
```

Output:

```go
"I was encrypted with the latest key"
"I may from a different epoch but still decryptable"
```

## Licence

```
Copyright 2017 Black Square Media Ltd

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
