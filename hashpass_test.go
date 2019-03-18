package hashpass

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

var getHashTypeTests = []struct {
	name   string
	input  string
	result HashPass
	err    error
}{
	{
		name:  "md5 ok",
		input: "$1$oNAuG282$IJK4Qq1ySC1tW03dYg7XS.",
		result: HashPass{
			Type: MD5,
			Salt: "$1$oNAuG282$",
			Hash: "$1$oNAuG282$IJK4Qq1ySC1tW03dYg7XS.",
		},
	},
	{
		name:  "sha256 ok",
		input: "$5$1bM59POonOkcgZVg$RxBd8wjmi1naVedaL9Gc/f7IVUEYHXsdhw/N4Lt61kA",
		result: HashPass{
			Type: SHA256,
			Salt: "$5$1bM59POonOkcgZVg$",
			Hash: "$5$1bM59POonOkcgZVg$RxBd8wjmi1naVedaL9Gc/f7IVUEYHXsdhw/N4Lt61kA",
		},
	},
	{
		name:  "sha512 ok",
		input: "$6$1bM59POonOkcgZVg$wkE2WyviOAvbrBkUBwOWFkd7DNRlL19L7THcaTCslOqUmexhYA3cjIoymWVXwyBrr.4CdDyRe4aeteYWSWuLV.",
		result: HashPass{
			Type: SHA512,
			Salt: "$6$1bM59POonOkcgZVg$",
			Hash: "$6$1bM59POonOkcgZVg$wkE2WyviOAvbrBkUBwOWFkd7DNRlL19L7THcaTCslOqUmexhYA3cjIoymWVXwyBrr.4CdDyRe4aeteYWSWuLV.",
		},
	},
	{
		name:  "bad id",
		input: "$3$1bM59POonOkcgZVg$wkE2WyviOAvbrBkUBwOWFkd7DNRlL19L7THcaTCslOqUmexhYA3cjIoymWVXwyBrr.4CdDyRe4aeteYWSWuLV.",
		err:   ErrInvalidHashType,
	},
	{
		name:  "bad length",
		input: "$6$1bM59POonOkcgZVg$wkE2WyviOAvbrBkUBwOWFkd7DNRlL19L7THcaTCslOqUmexhYA3cjIoymWVXwyBrr.4CdDyRe4aeteYWSWuLV",
		err:   ErrInvalidLength,
	},
}

func TestParseHash(t *testing.T) {
	for _, tt := range getHashTypeTests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := ParseHash(tt.input)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.result.Type, hash.Type)
				assert.Equal(t, tt.result.Salt, hash.Salt)
				assert.Equal(t, tt.result.Hash, hash.Hash)
			}
		})
	}
}

var createHashTests = []struct {
	name     string
	salt     string
	password string
	result   HashPass
	err      error
}{
	{
		name:     "md5 ok",
		salt:     "$1$oNAuG282$",
		password: "password",
		result: HashPass{
			Type: MD5,
			Salt: "$1$oNAuG282$",
			Hash: "$1$oNAuG282$IJK4Qq1ySC1tW03dYg7XS.",
		},
	},
	{
		name:     "sha256 ok",
		salt:     "$5$1bM59POonOkcgZVg$",
		password: "password",
		result: HashPass{
			Type: SHA256,
			Salt: "$5$1bM59POonOkcgZVg$",
			Hash: "$5$1bM59POonOkcgZVg$RxBd8wjmi1naVedaL9Gc/f7IVUEYHXsdhw/N4Lt61kA",
		},
	},
	{
		name:     "sha512 ok",
		salt:     "$6$1bM59POonOkcgZVg$",
		password: "password",
		result: HashPass{
			Type: SHA512,
			Salt: "$6$1bM59POonOkcgZVg$",
			Hash: "$6$1bM59POonOkcgZVg$wkE2WyviOAvbrBkUBwOWFkd7DNRlL19L7THcaTCslOqUmexhYA3cjIoymWVXwyBrr.4CdDyRe4aeteYWSWuLV.",
		},
	},
	{
		name:     "bad id",
		salt:     "$3$1bM59POonOkcgZVg$",
		password: "password",
		err:      ErrInvalidHashType,
	},
}

func TestHash(t *testing.T) {
	for _, tt := range createHashTests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := Hash(tt.salt, tt.password)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.result.Type, hash.Type)
				assert.Equal(t, tt.result.Salt, hash.Salt)
				assert.Equal(t, tt.result.Hash, hash.Hash)
			}
		})
	}
}

var createMD5HashTests = []struct {
	name     string
	password string
	result   HashPass
	err      error
}{
	{
		name:     "md5 ok",
		password: "password",
		result: HashPass{
			Type: MD5,
			Salt: "$1$wvOAvb7D$",
			Hash: "$1$wvOAvb7D$htWupjYcLZjgpDHn04K.O1",
		},
	},
}

func TestMD5Hash(t *testing.T) {
	Stubs()

	for _, tt := range createMD5HashTests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := MD5Hash(tt.password)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.result.Type, hash.Type)
				assert.Equal(t, tt.result.Salt, hash.Salt)
				assert.Equal(t, tt.result.Hash, hash.Hash)
			}
		})
	}

	StubsRestore()
}

var createSHA256HashTests = []struct {
	name     string
	password string
	result   HashPass
	err      error
}{
	{
		name:     "md5 ok",
		password: "password",
		result: HashPass{
			Type: SHA256,
			Salt: "$5$AvbrBkUBwOWFkd7D$",
			Hash: "$5$AvbrBkUBwOWFkd7D$QW/gpr1OPmBUjOjlFcvSuq/yMMubahx0PDFHhiKTjk2",
		},
	},
}

func TestSHA256Hash(t *testing.T) {
	Stubs()

	for _, tt := range createSHA256HashTests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := SHA256Hash(tt.password)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.result.Type, hash.Type)
				assert.Equal(t, tt.result.Salt, hash.Salt)
				assert.Equal(t, tt.result.Hash, hash.Hash)
			}
		})
	}

	StubsRestore()
}

var createSHA512HashTests = []struct {
	name     string
	password string
	result   HashPass
	err      error
}{
	{
		name:     "md5 ok",
		password: "password",
		result: HashPass{
			Type: SHA512,
			Salt: "$6$wkE2WyviOAvbkUBw$",
			Hash: "$6$wkE2WyviOAvbkUBw$QyIQH0npdzuhZX/JfTT7bEt7yJVUkL/as8GfR1HE3web.0y/O1i1s9kEs6eQ/0DzvXQRE48LmQm6aaXyqMahl.",
		},
	},
}

func TestSHA512Hash(t *testing.T) {
	Stubs()

	for _, tt := range createSHA512HashTests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := SHA512Hash(tt.password)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.result.Type, hash.Type)
				assert.Equal(t, tt.result.Salt, hash.Salt)
				assert.Equal(t, tt.result.Hash, hash.Hash)
			}
		})
	}

	StubsRestore()
}

var verifyHashTests = []struct {
	name     string
	hash     string
	password string
	result   bool
	err      error
}{
	{
		name:     "md5 ok",
		hash:     "$1$oNAuG282$IJK4Qq1ySC1tW03dYg7XS.",
		password: "password",
		result:   true,
	},
	{
		name:     "md5 trailing s",
		hash:     "$1$oNAuG282$IJK4Qq1ySC1tW03dYg7XS.",
		password: "passwords",
		result:   false,
	},
	{
		name:     "md5  missing last char",
		hash:     "$1$oNAuG282$IJK4Qq1ySC1tW03dYg7XS.",
		password: "passwor",
		result:   false,
	},
	{
		name:     "sha256 ok",
		hash:     "$5$1bM59POonOkcgZVg$RxBd8wjmi1naVedaL9Gc/f7IVUEYHXsdhw/N4Lt61kA",
		password: "password",
		result:   true,
	},
	{
		name:     "sha256 trailing s",
		hash:     "$5$1bM59POonOkcgZVg$RxBd8wjmi1naVedaL9Gc/f7IVUEYHXsdhw/N4Lt61kA",
		password: "passwords",
		result:   false,
	},
	{
		name:     "sha256 missing last char",
		hash:     "$5$1bM59POonOkcgZVg$RxBd8wjmi1naVedaL9Gc/f7IVUEYHXsdhw/N4Lt61kA",
		password: "passwor",
		result:   false,
	},
	{
		name:     "sha512 ok",
		hash:     "$6$1bM59POonOkcgZVg$wkE2WyviOAvbrBkUBwOWFkd7DNRlL19L7THcaTCslOqUmexhYA3cjIoymWVXwyBrr.4CdDyRe4aeteYWSWuLV.",
		password: "password",
		result:   true,
	},
	{
		name:     "sha512 trailing s",
		hash:     "$6$1bM59POonOkcgZVg$wkE2WyviOAvbrBkUBwOWFkd7DNRlL19L7THcaTCslOqUmexhYA3cjIoymWVXwyBrr.4CdDyRe4aeteYWSWuLV.",
		password: "passwords",
		result:   false,
	},
	{
		name:     "sha512 missing last char",
		hash:     "$6$1bM59POonOkcgZVg$wkE2WyviOAvbrBkUBwOWFkd7DNRlL19L7THcaTCslOqUmexhYA3cjIoymWVXwyBrr.4CdDyRe4aeteYWSWuLV.",
		password: "passwor",
		result:   false,
	},
	{
		name:     "bad id",
		hash:     "$3$1bM59POonOkcgZVg$",
		password: "password",
		err:      ErrInvalidHashType,
	},
}

func TestVerify(t *testing.T) {
	for _, tt := range verifyHashTests {
		t.Run(tt.name, func(t *testing.T) {
			verify, err := Verify(tt.hash, tt.password)
			if tt.err != nil {
				assert.EqualError(t, err, tt.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.result, verify)
			}
		})
	}
}

func BenchmarkMD5Hash(b *testing.B) {
	var hash HashPass
	var err error

	for n := 0; n < b.N; n++ {
		hash, err = MD5Hash("7Jh29J49Q9hgLYHxQMduzFcTkwrz5AB4")

		if err != nil {
			b.Fatalf(err.Error())
		}
	}

	if hash.Hash == "" {
		b.Fatalf("something went wrong")
	}
}

func BenchmarkSHA256Hash(b *testing.B) {
	var hash HashPass
	var err error

	for n := 0; n < b.N; n++ {
		hash, err = SHA256Hash("7Jh29J49Q9hgLYHxQMduzFcTkwrz5AB4")

		if err != nil {
			b.Fatalf(err.Error())
		}
	}

	if hash.Hash == "" {
		b.Fatalf("something went wrong")
	}
}

func BenchmarkSHA512Hash(b *testing.B) {
	var hash HashPass
	var err error

	for n := 0; n < b.N; n++ {
		hash, err = SHA512Hash("7Jh29J49Q9hgLYHxQMduzFcTkwrz5AB4")

		if err != nil {
			b.Fatalf(err.Error())
		}
	}

	if hash.Hash == "" {
		b.Fatalf("something went wrong")
	}
}

func ExampleHash() {
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

func ExampleMD5Hash() {
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

func ExampleSHA256Hash() {
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

func ExampleSHA512Hash() {
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

func ExampleVerify() {
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
