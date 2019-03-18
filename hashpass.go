package hashpass

import (
	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/md5_crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	"strings"
)

// HashPass defines the resulting object for all the hashpass functions
type HashPass struct {
	Type string
	Salt string
	Hash string
}

func getHashType(input string) (result string, err error) {
	result = ""
	err = nil

	if strings.HasPrefix(input, MD5) {
		result = MD5
	} else if strings.HasPrefix(input, SHA256) {
		result = SHA256
	} else if strings.HasPrefix(input, SHA512) {
		result = SHA512
	} else {
		err = ErrInvalidHashType
	}

	return
}

func getSalt(input string) (result string, err error) {
	result = ""
	err = nil

	index := 0

	// salt contains $*$***$, so we search for the third $
	for i := 0; i < 3; i++ {
		index = strings.Index(input[index+i:], "$")
		if index < 0 {
			err = ErrInvalidSalt
			return
		}
	}

	result = input[0 : index+4]

	return
}

func checkLength(hashType string, input string) (err error) {
	err = nil

	if hashType == MD5 {
		if len(input) != 34 {
			err = ErrInvalidLength
		}
	} else if hashType == SHA256 {
		if len(input) != 63 {
			err = ErrInvalidLength
		}
	} else if hashType == SHA512 {
		if len(input) != 106 {
			err = ErrInvalidLength
		}
	} else {
		err = ErrInvalidHashType
	}

	return
}

// ParseHash parses a password hash and deduces the type,
// salt, and verifies format is correct
func ParseHash(input string) (result HashPass, err error) {
	result.Type = ""
	result.Salt = ""
	result.Hash = input
	err = nil

	result.Type, err = getHashType(input)
	if err != nil {
		return
	}

	err = checkLength(result.Type, input)
	if err != nil {
		return
	}

	result.Salt, err = getSalt(input)
	if err != nil {
		return
	}

	return
}

func createKnownHashType(hashType string, salt string, password string) (result HashPass, err error) {
	result.Type = hashType
	result.Salt = salt
	result.Hash = ""
	err = nil

	var crypter crypt.Crypter

	if hashType == MD5 {
		crypter = crypt.MD5.New()
	} else if hashType == SHA256 {
		crypter = crypt.SHA256.New()
	} else if hashType == SHA512 {
		crypter = crypt.SHA512.New()
	} else {
		err = ErrInvalidHashType
		return
	}

	result.Hash, err = crypter.Generate([]byte(password), []byte(salt))
	if err != nil {
		return
	}

	return
}

// Hash creates a hash from a known salt
func Hash(salt string, password string) (result HashPass, err error) {
	result.Type = ""
	result.Salt = ""
	result.Hash = ""
	err = nil

	var hashType string

	hashType, err = getHashType(salt)
	if err != nil {
		return
	}

	result, err = createKnownHashType(hashType, salt, password)

	return
}

// MD5Hash creates a new MD5 hash from a randomly generated salt
func MD5Hash(password string) (result HashPass, err error) {
	result.Type = ""
	result.Salt = ""
	result.Hash = ""
	err = nil

	var randSeed string
	randSeed, err = DepGetRandomMD5Seed()

	if err != nil {
		return
	}

	salt := MD5 + "$" + randSeed + "$"

	result, err = createKnownHashType(MD5, salt, password)

	return
}

// SHA256Hash creates a new SHA256 hash from a randomly generated salt
func SHA256Hash(password string) (result HashPass, err error) {
	result.Type = ""
	result.Salt = ""
	result.Hash = ""
	err = nil

	var randSeed string
	randSeed, err = DepGetRandomSHA256Seed()

	if err != nil {
		return
	}

	salt := SHA256 + "$" + randSeed + "$"

	result, err = createKnownHashType(SHA256, salt, password)

	return
}

// SHA512Hash creates a new SHA512 hash from a randomly generated salt
func SHA512Hash(password string) (result HashPass, err error) {
	result.Type = ""
	result.Salt = ""
	result.Hash = ""
	err = nil

	var randSeed string
	randSeed, err = DepGetRandomSHA512Seed()

	if err != nil {
		return
	}

	salt := SHA512 + "$" + randSeed + "$"

	result, err = createKnownHashType(SHA512, salt, password)

	return
}

// Verify verifies that a password matches the computed hash
func Verify(hash string, password string) (result bool, err error) {
	result = false
	err = nil
	var inhash HashPass
	var testhash HashPass

	inhash, err = ParseHash(hash)

	if err != nil {
		return
	}

	testhash, err = Hash(inhash.Salt, password)

	if err != nil {
		return
	}

	if inhash.Hash == testhash.Hash {
		result = true
	}

	return
}
