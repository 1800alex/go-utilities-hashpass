package hashpass

import (
	"github.com/1800alex/go-utilities-password"
)

// DepGetRandomMD5Seed is an external dependancy wrapper
// to get a random 8 character seed.
var DepGetRandomMD5Seed = func() (result string, err error) {
	result, err = password.Generate(8, true, false, false, true)
	return
}

// DepGetRandomSHA256Seed is an external dependancy wrapper
// to get a random 16 character seed.
var DepGetRandomSHA256Seed = func() (result string, err error) {
	result, err = password.Generate(16, true, false, false, true)
	return
}

// DepGetRandomSHA512Seed is an external dependancy wrapper
// to get a random 16 character seed.
var DepGetRandomSHA512Seed = func() (result string, err error) {
	result, err = password.Generate(16, true, false, false, true)
	return
}
