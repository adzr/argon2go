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

/*
Package argon2go contains a simple argon2 <https://github.com/P-H-C/phc-winner-argon2/> binding
inspired by go-argon <https://github.com/tvdburgt/go-argon2>.

Brief

The package offers a simple interface Hasher with argon2 default C binding implementation,
the implementation implicitly generates salt based on a secure random byte array while encoding.

Usage

Be sure that you have argon2 development C library is installed correctly along with its header
on your system, then get the this library:

  $ go get -u github.com/adzr/argon2go

Then, import the package:

  import (
    "github.com/adzr/argon2go"
  )

Example

Create an argon2 hasher with the default options:

  // Iterations: 8
  // Memory: 65536 KB
  // Parallelism: 8
  // HashLength: 64
  // SaltLength: 64
  // Mode: Argon2ModeID
  // Version: Argon2Version13
  hasher := argon2go.CreateArgon2()

Options can be specified in the following way:

  hasher := argon2go.CreateArgon2(argon2go.Argon2Parallelism(4), argon2go.Argon2HashLength(32))

Once you have a hasher instance, you can call the encode and verify functions:

  var (
    err error
    hashed []byte
    verified bool
  )

  if hashed, err = hasher.Encode([]byte(secretString)); err != nil {
    panic(err) // or handle however you want.
  }

  if verified, err = hasher.Verify([]byte(secretString), hashed); err != nil {
    panic(err)
  }

  println(verified) // This should output true.

*/
package argon2go
