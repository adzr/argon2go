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

import (
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

const (
	CorrectPassPhrase   = "TrueSecretPassPhrase"
	CorrectEncoding     = "$argon2id$v=19$m=65535,t=16,p=8$MUh1TFVfaXZiNmFnU1BmZHpKYjE3V1BSU3hKT0Z5TzNzVlJSbUZvTXJQS2k2QktRWWRZOFJEc3daNXlCXzhfWnpESlNBeW0zcmZYQWo2WGxKTW51cUE9PQ$t2HezttHhC/RqkDRG9S9OMXjkUbmGORqzzviDXIw8lA"
	IncorrectPassPhrase = "BadPassPhrase"
	BadMemoryEncoding   = "$argon2id$v=19$m=0,t=16,p=8$MUh1TFVfaXZiNmFnU1BmZHpKYjE3V1BSU3hKT0Z5TzNzVlJSbUZvTXJQS2k2QktRWWRZOFJEc3daNXlCXzhfWnpESlNBeW0zcmZYQWo2WGxKTW51cUE9PQ$t2HezttHhC/RqkDRG9S9OMXjkUbmGORqzzviDXIw8lA"
	BadModeEncoding     = "$argon2k$v=19$m=65536,t=5,p=8$elFNSmhRa2JYdUY4cGc2NXZqUUdoUGJmc1M1VFkxSjh4aWU4cT" +
		"A0elh5d2k5TVRfN1hqSEVqSDRKT0gteG5OUHkzOEw2OG5zZWdhNFJ6UDVQSTJhc1E9PQ$lo2264d+4pS9yPvTXOZE/sdqc" +
		"Gz6fFb0o5hqTz1F/2c"
	IncorrectEncoding = "$argon2i$v=19$m=65536,t=5,p=8$elFNSmhRa2JYdUY4cGc2NXZqUUdoUGJmc1M1VFkxSjh4aWU4cT" +
		"A0elh5d2k5TVRfN1hqSEVqSDRKT0gteG5OUHkzOEw2OG5zZWdhNFJ6UDVQSTJhc1E9PQ$lo2264d+4pS9yPvTXOZE/sdqc" +
		"Gz6fFb0o5hqTz1F/2c"
)

type failingReader struct {
}

func (*failingReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("failed")
}

type Argon2TestSuite struct {
	suite.Suite
	hasher Hasher
}

func (suite *Argon2TestSuite) SetupTest() {
	suite.hasher = CreateArgon2(Argon2HashLength(64))
}

func (suite *Argon2TestSuite) TestArgon2_Encode_Verify_Success() {
	encoded, err := suite.hasher.Encode([]byte(CorrectPassPhrase))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), encoded)

	shouldBeTrue, err := suite.hasher.Verify([]byte(CorrectPassPhrase), encoded)

	assert.Nil(suite.T(), err)
	assert.True(suite.T(), shouldBeTrue)
}

func (suite *Argon2TestSuite) TestArgon2_Encode_Verify_Mismatch() {
	encoded, err := suite.hasher.Encode([]byte(CorrectPassPhrase))
	assert.Nil(suite.T(), err)
	assert.NotNil(suite.T(), encoded)

	shouldBeFalse, err := suite.hasher.Verify([]byte(IncorrectPassPhrase), []byte(encoded))

	assert.Nil(suite.T(), err)
	assert.False(suite.T(), shouldBeFalse)
}

func (suite *Argon2TestSuite) TestArgon2_Encode_Failure_EmptyInput() {
	hash, err := suite.hasher.Encode([]byte(""))
	assert.Empty(suite.T(), hash)
	assert.EqualError(suite.T(), err, ErrEmptyInput.Error())
}

func (suite *Argon2TestSuite) TestArgon2_Encode_Failure_NilInput() {
	hash, err := suite.hasher.Encode(nil)
	assert.Empty(suite.T(), hash)
	assert.EqualError(suite.T(), err, ErrEmptyInput.Error())
}

func (suite *Argon2TestSuite) TestArgon2_Verify_Failure_EmptyInput() {
	hash, err := suite.hasher.Verify([]byte(""), []byte(""))
	assert.Empty(suite.T(), hash)
	assert.EqualError(suite.T(), err, ErrEmptyInput.Error())
}

func (suite *Argon2TestSuite) TestArgon2_Verify_Failure_NilInput() {
	hash, err := suite.hasher.Verify(nil, nil)
	assert.Empty(suite.T(), hash)
	assert.EqualError(suite.T(), err, ErrEmptyInput.Error())
}

func (suite *Argon2TestSuite) TestArgon2_Verify_Failure_EmptyHash() {
	hash, err := suite.hasher.Verify([]byte(CorrectPassPhrase), []byte(""))
	assert.Empty(suite.T(), hash)
	assert.EqualError(suite.T(), err, ErrEmptyHash.Error())
}

func (suite *Argon2TestSuite) TestArgon2_Verify_Failure_NilHash() {
	hash, err := suite.hasher.Verify([]byte(CorrectPassPhrase), nil)
	assert.Empty(suite.T(), hash)
	assert.EqualError(suite.T(), err, ErrEmptyHash.Error())
}

func (suite *Argon2TestSuite) TestArgon2_Verify_Failure_BadMode() {
	hash, err := suite.hasher.Verify([]byte(CorrectPassPhrase), []byte(BadModeEncoding))
	assert.Empty(suite.T(), hash)
	assert.EqualError(suite.T(), err, ErrInvalidArgon2Mode.Error())
}

func TestArgon2TestSuite(t *testing.T) {
	suite.Run(t, new(Argon2TestSuite))
}

func (suite *Argon2TestSuite) TestArgon2_Encode_NilConf() {
	suite.hasher.(*argon2Hasher).conf = nil
	hash, err := suite.hasher.Encode([]byte(""))
	assert.Empty(suite.T(), hash)
	assert.EqualError(suite.T(), err, ErrNotConfigured.Error())
}

func (suite *Argon2TestSuite) TestArgon2_Verify_NilConf() {
	suite.hasher.(*argon2Hasher).conf = nil
	verified, err := suite.hasher.Verify([]byte(""), []byte(""))
	assert.False(suite.T(), verified)
	assert.EqualError(suite.T(), err, ErrNotConfigured.Error())
}

func (suite *Argon2TestSuite) TestArgon2_Encode_BadSaltConfiguration() {
	suite.hasher.(*argon2Hasher).conf.SaltLength = 0
	hash, err := suite.hasher.Encode([]byte(CorrectPassPhrase))
	assert.Empty(suite.T(), hash)
	assert.EqualError(suite.T(), err, ErrNotConfigured.Error())
}

func (suite *Argon2TestSuite) TestArgon2_Encode_FailedSaltGeneration() {
	var reader io.Reader
	rand.Reader, reader = &failingReader{}, rand.Reader
	hash, err := suite.hasher.Encode([]byte(CorrectPassPhrase))
	rand.Reader = reader
	assert.Empty(suite.T(), hash)
	assert.EqualError(suite.T(), err, "failed")
}

func (suite *Argon2TestSuite) TestArgon2_Encode_BadMemorySpace() {
	suite.hasher.(*argon2Hasher).conf.Memory = 0
	hash, err := suite.hasher.Encode([]byte(CorrectPassPhrase))
	assert.Empty(suite.T(), hash)
	assert.NotNil(suite.T(), err)
}

func (suite *Argon2TestSuite) TestArgon2_Verify_BadMemorySpace() {
	suite.hasher.(*argon2Hasher).conf.Memory = 0
	hash, err := suite.hasher.Verify([]byte(CorrectPassPhrase), []byte(BadMemoryEncoding))
	assert.Empty(suite.T(), hash)
	assert.NotNil(suite.T(), err)
}

func TestGetArgon2Mode(t *testing.T) {
	var mode int
	var err error

	mode, err = getArgon2Mode([]byte("$argon2id"))
	assert.Equal(t, Argon2ModeID, mode)
	assert.Nil(t, err)

	mode, err = getArgon2Mode([]byte("$argon2i"))
	assert.Equal(t, Argon2ModeI, mode)
	assert.Nil(t, err)

	mode, err = getArgon2Mode([]byte("$argon2d"))
	assert.Equal(t, Argon2ModeD, mode)
	assert.Nil(t, err)

	mode, err = getArgon2Mode([]byte("invalidInput"))
	assert.Equal(t, -1, mode)
	assert.EqualError(t, err, ErrInvalidArgon2Mode.Error())

	mode, err = getArgon2Mode([]byte(""))
	assert.Equal(t, -1, mode)
	assert.EqualError(t, err, ErrInvalidArgon2Mode.Error())

	mode, err = getArgon2Mode(nil)
	assert.Equal(t, -1, mode)
	assert.EqualError(t, err, ErrInvalidArgon2Mode.Error())
}

func TestArgon2Options(t *testing.T) {
	c := &Argon2Config{
		HashLength:  0,
		Iterations:  0,
		Memory:      0,
		Mode:        0,
		Parallelism: 0,
		SaltLength:  0,
		Version:     0,
	}

	Argon2HashLength(1)(c)
	Argon2Iterations(2)(c)
	Argon2Memory(3)(c)
	Argon2Mode(4)(c)
	Argon2Parallelism(5)(c)
	Argon2SaltLength(6)(c)
	Argon2Version(7)(c)

	assert.Equal(t, 1, c.HashLength)
	assert.Equal(t, 2, c.Iterations)
	assert.Equal(t, 3, c.Memory)
	assert.Equal(t, 4, c.Mode)
	assert.Equal(t, 5, c.Parallelism)
	assert.Equal(t, 6, c.SaltLength)
	assert.Equal(t, 7, c.Version)
}

func runArgon2EncodeBenchmark(hasher Hasher, b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := hasher.Encode([]byte(CorrectPassPhrase)); err != nil {
				println(err.Error())
			}
		}
	})
}

func createArgon2UDv13Hasher(parallelism, memory, iterations int) Hasher {
	return CreateArgon2(
		Argon2Mode(Argon2ModeID),
		Argon2Version(Argon2Version13),
		Argon2Memory(memory*1024),
		Argon2Parallelism(parallelism),
		Argon2Iterations(iterations),
	)
}

func BenchmarkArgon2_Encode_IDv13_P8_M128mb_T1(b *testing.B) {
	runArgon2EncodeBenchmark(createArgon2UDv13Hasher(8, 256, 5), b)
}
