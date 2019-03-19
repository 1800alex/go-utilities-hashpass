# hashpass [![GoDoc](https://godoc.org/github.com/1800alex/go-utilities-hashpass?status.svg)](https://godoc.org/github.com/1800alex/go-utilities-hashpass)
[![Build Status](https://travis-ci.com/1800alex/go-utilities-hashpass.svg?branch=master)](https://travis-ci.com/1800alex/go-utilities-hashpass)
[![Coverage Status](https://coveralls.io/repos/github/1800alex/go-utilities-hashpass/badge.svg?branch=master)](https://coveralls.io/github/1800alex/go-utilities-hashpass?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/1800alex/go-utilities-hashpass)](https://goreportcard.com/report/github.com/1800alex/go-utilities-hashpass)


Package hashpass is a package capable parsing and generating libc compatible password hashes If salt is a character string starting with the characters "$id$" followed by a string terminated by "$": $id$salt$encrypted then instead of using the DES machine, id identifies the encryption method used and this then determines how the rest of the password string is interpreted.

Download:
```shell
go get github.com/1800alex/go-utilities-hashpass
```

* * *
Package hashpass is a package capable parsing and generating libc compatible password hashes

```
If salt is a character string starting with the characters
"$id$" followed by a string terminated by "$":

	$id$salt$encrypted

then instead of using the DES machine, id identifies the
encryption method used and this then determines how the rest
of the password string is interpreted.  The following values
of id are supported:

		ID  | Method
		─────────────────────────────────────────────────────────
		1   | MD5
		2a  | Blowfish (not in mainline glibc; added in some
			| Linux distributions, not supported by this package)
		5   | SHA-256 (since glibc 2.7)
		6   | SHA-512 (since glibc 2.7)

So $5$salt$encrypted is an SHA-256 encoded password and
$6$salt$encrypted is an SHA-512 encoded one.

"salt" stands for the up to 16 characters following "$id$" in
the salt.  The encrypted part of the password string is the
actual computed password.  The size of this string is fixed:

MD5     | 22 characters
SHA-256 | 43 characters
SHA-512 | 86 characters
```





# Examples

Hash
Code:

```
{
	var hash HashPass
	var err error
	hash, err = Hash("$6$1bM59POonOkcgZVg$", "7Jh29J49Q9hgLYHxQMduzFcTkwrz5AB4")
	if err != nil {
		fmt.Println(err.Error())
	}
	if hash.Hash == "" {
		fmt.Println("something went wrong")
	}
}
```


MD5Hash
Code:

```
{
	var hash HashPass
	var err error
	hash, err = MD5Hash("7Jh29J49Q9hgLYHxQMduzFcTkwrz5AB4")
	if err != nil {
		fmt.Println(err.Error())
	}
	if hash.Hash == "" {
		fmt.Println("something went wrong")
	}
}
```


SHA256Hash
Code:

```
{
	var hash HashPass
	var err error
	hash, err = SHA256Hash("7Jh29J49Q9hgLYHxQMduzFcTkwrz5AB4")
	if err != nil {
		fmt.Println(err.Error())
	}
	if hash.Hash == "" {
		fmt.Println("something went wrong")
	}
}
```


SHA512Hash
Code:

```
{
	var hash HashPass
	var err error
	hash, err = SHA512Hash("7Jh29J49Q9hgLYHxQMduzFcTkwrz5AB4")
	if err != nil {
		fmt.Println(err.Error())
	}
	if hash.Hash == "" {
		fmt.Println("something went wrong")
	}
	fmt.Println(hash.Hash)
}
```


Verify
Code:

```
{
	var verify bool
	var err error
	verify, err = Verify("$1$oNAuG282$IJK4Qq1ySC1tW03dYg7XS.", "password")
	if err != nil {
		fmt.Println(err.Error())
	}
	if verify == false {
		fmt.Println("incorrect password")
	} else {
		fmt.Println("correct password")
	}
}
```



