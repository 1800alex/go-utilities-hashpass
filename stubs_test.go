package hashpass

import ()

var oldDepGetRandomMD5Seed = DepGetRandomMD5Seed
var oldDepGetRandomSHA256Seed = DepGetRandomSHA256Seed
var oldDepGetRandomSHA512Seed = DepGetRandomSHA512Seed

var StubDepGetRandomMD5Seed = func() (result string, err error) {
	result = "wvOAvb7D"
	err = nil
	return
}

var StubDepGetRandomSHA256Seed = func() (result string, err error) {
	result = "AvbrBkUBwOWFkd7D"
	err = nil
	return
}

var StubDepGetRandomSHA512Seed = func() (result string, err error) {
	result = "wkE2WyviOAvbkUBw"
	err = nil
	return
}

func Stubs() {
	DepGetRandomMD5Seed = StubDepGetRandomMD5Seed
	DepGetRandomSHA256Seed = StubDepGetRandomSHA256Seed
	DepGetRandomSHA512Seed = StubDepGetRandomSHA512Seed
}

func StubsRestore() {
	DepGetRandomMD5Seed = oldDepGetRandomMD5Seed
	DepGetRandomSHA256Seed = oldDepGetRandomSHA256Seed
	DepGetRandomSHA512Seed = oldDepGetRandomSHA512Seed
}
