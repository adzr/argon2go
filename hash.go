/*
Copyright 2018 Ahmed Zaher

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

// Hasher is a common interface that represents a hashing
// algorithm implementation.
type Hasher interface {
	// Encode receives a byte array and returns its hash
	// representation as a byte array depending on the
	// algorithm implemented, it also may return an error
	// with a nil byte array on failure.
	Encode([]byte) ([]byte, error)

	// Verify receives two byte arrays and simply checks
	// if the second represents the hash value of the
	// first, if they match it returns true, else false.
	// It also returns an error on failure to check.
	Verify([]byte, []byte) (bool, error)
}
