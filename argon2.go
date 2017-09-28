/*
Copyright 2017 Ahmed Zaher

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package argon2go

// #cgo CFLAGS: -I/usr/include
// #cgo LDFLAGS: -L/usr/lib -largon2
// #include <stdlib.h>
// #include <argon2.h>
import "C"

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"unsafe"
)

const (
	// Argon2ModeD is a constant value flag represents argon2d mode in argon2 algorithm.
	Argon2ModeD int = C.Argon2_d

	// Argon2ModeI is a constant value flag represents argon2i mode in argon2 algorithm.
	Argon2ModeI int = C.Argon2_i

	// Argon2ModeID is a constant value flag represents argon2id mode in argon2 algorithm.
	Argon2ModeID int = C.Argon2_id

	// Argon2Version10 is a constant value flag represents argon2 implementation version 10.
	Argon2Version10 int = C.ARGON2_VERSION_10

	// Argon2Version13 is a constant value flag represents argon2 implementation version 13.
	Argon2Version13 int = C.ARGON2_VERSION_13

	// Argon2VersionDefault is a constant value flag represents argon2 implementation default version.
	Argon2VersionDefault int = C.ARGON2_VERSION_NUMBER
)

var (
	// ErrEmptyInput returned if the raw input parameter is nil or empty on calling Encode or Verify.
	ErrEmptyInput = errors.New("empty input specified")

	// ErrEmptyHash returned if the hash parameter is nil or empty on calling Verify.
	ErrEmptyHash = errors.New("empty hash specified")

	// ErrNotConfigured returned on calling Encode or Verify
	// if the Argon2 Hasher instance is not configured.
	ErrNotConfigured = errors.New("instance is not configured properly")

	// ErrInvalidArgon2Mode returned on calling Verify if the Argon2 mode
	// extracted from the specified hash is invalid.
	ErrInvalidArgon2Mode = errors.New("invalid argon2 mode")
)

// Argon2Config is a configuration struct
// meant to carry Argon2 configuration
// through the initialization process.
type Argon2Config struct {
	// Iterations is the number of iterations, more
	// iterations, more secure hash but slower hashing.
	Iterations int

	// Memory is the memory cost in kilobytes
	// requested to process the hash function.
	Memory int

	// Parallelism is the number of concurrent passes
	// used in the hash function.
	Parallelism int

	// HashLength is the length in bytes of the hash output.
	HashLength int

	// SaltLength is the length in bytes of the salt.
	SaltLength int

	// Mode is the variation of algorithm meant to be used.
	// Possible values:
	// Argon2ModeD
	// Argon2ModeI
	// Argon2ModeID
	Mode int

	// Version is the used algorithm version.
	// Possible values:
	// Argon2Version10
	// Argon2Version13
	// Argon2VersionDefault
	Version int
}

type argon2Hasher struct {
	conf *Argon2Config
}

// Argon2Option is a callback function that is meant
// to configure a provided reference to Argon2Config
// structure.
type Argon2Option func(conf *Argon2Config)

// Argon2Iterations returns an Argon2Option that
// configures a provided reference of Argon2Config
// with the specified iterations.
func Argon2Iterations(iterations int) Argon2Option {
	return func(conf *Argon2Config) {
		conf.Iterations = iterations
	}
}

// Argon2Memory returns an Argon2Option that
// configures a provided reference of Argon2Config
// with the specified memory size in kilobytes.
func Argon2Memory(memory int) Argon2Option {
	return func(conf *Argon2Config) {
		conf.Memory = memory
	}
}

// Argon2Parallelism returns an Argon2Option that
// configures a provided reference of Argon2Config
// with the specified number of passes (parallelism).
func Argon2Parallelism(parallelism int) Argon2Option {
	return func(conf *Argon2Config) {
		conf.Parallelism = parallelism
	}
}

// Argon2HashLength returns an Argon2Option that
// configures a provided reference of Argon2Config
// with the specified hash length in bytes.
func Argon2HashLength(hashLength int) Argon2Option {
	return func(conf *Argon2Config) {
		conf.HashLength = hashLength
	}
}

// Argon2SaltLength returns an Argon2Option that
// configures a provided reference of Argon2Config
// with the specified salt length in bytes.
func Argon2SaltLength(saltLength int) Argon2Option {
	return func(conf *Argon2Config) {
		conf.SaltLength = saltLength
	}
}

// Argon2Mode returns an Argon2Option that
// configures a provided reference of Argon2Config
// with the specified mode.
func Argon2Mode(mode int) Argon2Option {
	return func(conf *Argon2Config) {
		conf.Mode = mode
	}
}

// Argon2Version returns an Argon2Option that
// configures a provided reference of Argon2Config
// with the specified version.
func Argon2Version(version int) Argon2Option {
	return func(conf *Argon2Config) {
		conf.Version = version
	}
}

// CreateArgon2 returns a reference to a Hasher implementation
// that uses Argon2 algorithm to hash and verify a secret.
// For more information on Argon2 refer to: https://github.com/P-H-C/phc-winner-argon2
func CreateArgon2(options ...Argon2Option) Hasher {
	conf := &Argon2Config{
		Iterations:  8,
		Memory:      1 << 16,
		Parallelism: 8,
		HashLength:  64,
		SaltLength:  64,
		Mode:        Argon2ModeID,
		Version:     Argon2Version13,
	}

	for _, opt := range options {
		opt(conf)
	}

	return &argon2Hasher{conf: conf}
}

func (h *argon2Hasher) Encode(raw []byte) ([]byte, error) {

	// Validating configuration.
	if h.conf == nil {
		return nil, ErrNotConfigured
	}

	// Validating input.
	if raw == nil || len(raw) == 0 {
		return nil, ErrEmptyInput
	}

	var err error
	var c = h.conf

	// Validating salt settings.
	if c.SaltLength == 0 {
		return nil, ErrNotConfigured
	}

	// Generating salt.
	var salt = make([]byte, c.SaltLength)

	if _, err = rand.Read(salt); err != nil {
		return nil, err
	}

	// Determine the ecoded string length.
	encodedlength := C.argon2_encodedlen(
		C.uint32_t(c.Iterations),
		C.uint32_t(c.Memory),
		C.uint32_t(c.Parallelism),
		C.uint32_t(len(salt)),
		C.uint32_t(c.HashLength),
		C.argon2_type(c.Mode))

	// Creating the buffer for the hash to be stored.
	hash := make([]byte, encodedlength)

	// Now calling the hash function.
	result := C.argon2_hash(
		C.uint32_t(c.Iterations),
		C.uint32_t(c.Memory),
		C.uint32_t(c.Parallelism),
		unsafe.Pointer(&raw[0]), C.size_t(len(raw)),
		unsafe.Pointer(&salt[0]), C.size_t(len(salt)),
		nil, C.size_t(c.HashLength),
		(*C.char)(unsafe.Pointer(&hash[0])), C.size_t(encodedlength),
		C.argon2_type(c.Mode),
		C.uint32_t(c.Version))

	if result != C.ARGON2_OK {
		return nil, errors.New(C.GoString(C.argon2_error_message(C.int(result))))
	}

	return bytes.TrimRight(hash, "\x00"), nil
}

func (h *argon2Hasher) Verify(raw, hash []byte) (bool, error) {

	if h.conf == nil {
		return false, ErrNotConfigured
	}

	if raw == nil || len(raw) == 0 {
		return false, ErrEmptyInput
	}

	if hash == nil || len(hash) == 0 {
		return false, ErrEmptyHash
	}

	var err error
	var mode int

	if mode, err = getArgon2Mode(hash); err != nil {
		return false, err
	}

	hashString := string(hash)
	cHashString := C.CString(hashString)
	defer C.free(unsafe.Pointer(cHashString))

	result := C.argon2_verify(
		cHashString,
		unsafe.Pointer(&raw[0]),
		C.size_t(len(raw)),
		C.argon2_type(mode))

	if result == C.ARGON2_OK {
		return true, nil
	} else if result == C.ARGON2_VERIFY_MISMATCH {
		return false, nil
	}

	return false, errors.New(C.GoString(C.argon2_error_message(C.int(result))))
}

func getArgon2Mode(hash []byte) (int, error) {

	if hash == nil || len(hash) == 0 {
		return -1, ErrInvalidArgon2Mode
	}

	hashString := string(hash)

	switch {
	case strings.HasPrefix(hashString, "$argon2id"):
		return Argon2ModeID, nil
	case strings.HasPrefix(hashString, "$argon2i"):
		return Argon2ModeI, nil
	case strings.HasPrefix(hashString, "$argon2d"):
		return Argon2ModeD, nil
	default:
		return -1, ErrInvalidArgon2Mode
	}
}
