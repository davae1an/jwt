# jwt (JSON Web Token for Go)
[![JWT compatible](https://jwt.io/img/badge.svg)](https://jwt.io)  

[![CircleCI](https://circleci.com/gh/gbrlsnchs/jwt.svg?style=shield)](https://circleci.com/gh/gbrlsnchs/jwt)
[![Go Report Card](https://goreportcard.com/badge/github.com/gbrlsnchs/jwt)](https://goreportcard.com/report/github.com/gbrlsnchs/jwt)
[![GoDoc](https://godoc.org/github.com/gbrlsnchs/jwt?status.svg)](https://godoc.org/github.com/gbrlsnchs/jwt)
[![Join the chat at https://gitter.im/gbrlsnchs/jwt](https://badges.gitter.im/gbrlsnchs/jwt.svg)](https://gitter.im/gbrlsnchs/jwt?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

## Compatibility
[![Version Compatibility](https://img.shields.io/badge/go%20modules-go1.11+-5272b4.svg)](https://github.com/gbrlsnchs/jwt#installing)
[![vgo](https://img.shields.io/badge/vgo-go1.10-5272b4.svg)](https://github.com/gbrlsnchs/jwt#installing)
[![go get](https://img.shields.io/badge/go%20get-go1.9.7+,%20go1.10.3+%20and%20go1.11-5272b4.svg)](https://github.com/gbrlsnchs/jwt#installing)

## About
This package is a JWT signer, verifier and validator for [Go](https://golang.org) (or Golang).

Although there are many JWT packages out there for Go, many lack support for some signing, verifying or validation methods and, when they don't, they're overcomplicated. This package tries to mimic the ease of use from [Node JWT library](https://github.com/auth0/node-jsonwebtoken)'s API while following the [Effective Go](https://golang.org/doc/effective_go.html) guidelines.

Support for [JWE](https://tools.ietf.org/html/rfc7516) isn't provided (not yet but is in the roadmap, see #17). Instead, [JWS](https://tools.ietf.org/html/rfc7515) is used, narrowed down to the [JWT specification](https://tools.ietf.org/html/rfc7519).

### Supported signing methods
|         | SHA-256            | SHA-384            | SHA-512            |
|:-------:|:------------------:|:------------------:|:------------------:|
| HMAC    | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| RSA     | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| RSA-PSS | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| ECDSA   | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| EdDSA   | :heavy_minus_sign: | :heavy_minus_sign: | :heavy_check_mark: |

## Important
Branch `master` is unstable, **always** use tagged versions. That way it is possible to differentiate pre-release tags from production ones.
In other words, API changes all the time in `master`. It's a place for public experiment. Thus, make use of the latest stable version via Go modules.

## Usage
Full documentation [here](https://godoc.org/github.com/gbrlsnchs/jwt).

### Installing
<details><summary><b>Go 1.12 onward</b></summary>
<p>

```sh
$ go get -u github.com/davae1an/jwt/v3
```

</p>
</details>

<details><summary><b>Go 1.11</b></summary>
<p>

```sh
$ GO111MODULE=on go get -u github.com/davae1an/jwt/v3
```

</p>
</details>

<details><summary><b>Go 1.10 with <code>vgo</code></b></summary>
<p>

```sh
$ vgo get -u github.com/davae1an/jwt/v3
```

</p>
</details>

<details><summary><b>Go 1.9.7+, Go 1.10.3+ (without <code>vgo</code>) and Go 1.11 (when <code>GO111MODULE=off</code>)</b></summary>
<p>

```sh
$ go get -u github.com/davae1an/jwt/v3
```

#### Important
Your project must be inside the `GOPATH`.

</p>
</details>

### Signing
```go
import (
	"time"

	"github.com/davae1an/jwt/v3"
)

type CustomPayload struct {
	jwt.Payload
	Foo string `json:"foo,omitempty"`
	Bar int    `json:"bar,omitempty"`
}

var hs = jwt.NewHS256([]byte("secret"))

func main() {
	now := time.Now()
	pl := CustomPayload{
		Payload: jwt.Payload{
			Issuer:         "gbrlsnchs",
			Subject:        "someone",
			Audience:       jwt.Audience{"https://golang.org", "https://jwt.io"},
			ExpirationTime: jwt.NumericDate(now.Add(24 * 30 * 12 * time.Hour)),
			NotBefore:      jwt.NumericDate(now.Add(30 * time.Minute)),
			IssuedAt:       jwt.NumericDate(now),
			JWTID:          "foobar",
		},
		Foo: "foo",
		Bar: 1337,
	}

	token, err := jwt.Sign(pl, hs)
	if err != nil {
		// ...
	}

	// ...
}
```

### Verifying
```go
import "github.com/davae1an/jwt/v3"

type CustomPayload struct {
	jwt.Payload
	Foo string `json:"foo,omitempty"`
	Bar int    `json:"bar,omitempty"`
}

var hs = jwt.NewHS256([]byte("secret"))

func main() {
	// ...

	var pl CustomPayload
	hd, err := jwt.Verify(token, hs, &pl)
	if err != nil {
		// ...
	}

	// ...
}
```

### Other use case examples
<details><summary><b>Setting "cty" and "kid" claims</b></summary>
<p>

The "cty" and "kid" claims can be set by passing options to the `jwt.Sign` function:
```go
import (
	"time"

	"github.com/davae1an/jwt/v3"
)

var hs = jwt.NewHS256([]byte("secret"))

func main() {
	pl := jwt.Payload{
		Subject:  "gbrlsnchs",
		Issuer:   "gsr.dev",
		IssuedAt: jwt.NumericDate(time.Now()),
	}

	token, err := jwt.Sign(pl, hs, jwt.ContentType("JWT"), jwt.KeyID("my_key"))
	if err != nil {
		// ...
	}

	// ...
}
```

</p>
</details>

<details><summary><b>Validating claims</b></summary>
<p>


```go
import (
	"time"

	"github.com/davae1an/jwt/v3"
)

type CustomPayload struct {
	jwt.Payload
	Foo string `json:"foo,omitempty"`
	Bar int    `json:"bar,omitempty"`
}

var hs = jwt.NewHS256([]byte("secret"))

func main() {
	// ...

	var (
		now = time.Now()
		aud = jwt.Audience{"https://golang.org"}

		// Validate claims "iat", "exp" and "aud".
		iatValidator = jwt.IssuedAtValidator(now)
		expValidator = jwt.ExpirationTimeValidator(now)
		audValidator = jwt.AudienceValidator(aud)

		// Use jwt.ValidatePayload to build a jwt.VerifyOption.
		// Validators are run in the order informed.
		pl              CustomPayload
		validatePayload = jwt.ValidatePayload(&pl.Payload, iatValidator, expValidator, audValidator)
	)

	hd, err := jwt.Verify(token, hs, &pl, validatePayload)
	if err != nil {
		// ...
	}

	// ...
}
```

</p>
</details>

<details><summary><b>Validating "alg" before verifying</b></summary>
<p>

For validating the "alg" field in a JOSE header **before** verification, the `jwt.ValidateHeader` option must be passed to `jwt.Verify`.
```go
import "github.com/davae1an/jwt/v3"

var hs = jwt.NewHS256([]byte("secret"))

func main() {
	// ...

	var pl jwt.Payload
	if _, err := jwt.Verify(token, hs, &pl, jwt.ValidateHeader); err != nil {
		// ...
	}

	// ...
}
```

</p>
</details>

<details><summary><b>Using an <code>Algorithm</code> resolver</b></summary>
<p>

```go
import (
	"errors"

	"github.com/davae1an/jwt/v3"
	"github.com/davae1an/jwt/v3/jwtutil"
)

var (
	// ...

	rs256 = jwt.NewRS256(jwt.RSAPublicKey(myRSAPublicKey))
	es256 = jwt.NewES256(jwt.ECDSAPublicKey(myECDSAPublicKey))
)

func main() {
	rv := &jwtutil.Resolver{New: func(hd jwt.Header) {
		switch hd.KeyID {
		case "foo":
			return rs256, nil
		case "bar":
			return es256, nil
		default:
			return nil, errors.New(`invalid "kid"`)
		}
	}}
	var pl jwt.Payload
	if _, err := jwt.Verify(token, rv, &pl); err != nil {
		// ...
	}

	// ...
}
```

</p>
</details>

## Contributing
### How to help
- For bugs and opinions, please [open an issue](https://github.com/gbrlsnchs/jwt/issues/new)
- For pushing changes, please [open a pull request](https://github.com/gbrlsnchs/jwt/compare)
