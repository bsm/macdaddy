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

func main() {{ "ExampleMAC" | code }}
```

Output:

```go
{{ "ExampleMAC" | output }}
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

func main() {{ "ExampleRing" | code }}
```

Output:

```go
{{ "ExampleRing" | output }}
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
