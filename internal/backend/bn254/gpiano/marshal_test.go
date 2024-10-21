// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Modifications Copyright 2023 Tianyi Liu and Tiancheng Xie

package gpiano

import (
	curve "github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"bytes"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

func TestProvingKeySerialization(t *testing.T) {
	// create a random vk
	var vk VerifyingKey
	vk.SizeY = 10
	vk.SizeYInv.SetOne()
	vk.SizeX = 42
	vk.SizeXInv = fr.One()
	vk.SizeXInv.Add(&vk.SizeXInv, &vk.SizeXInv)

	_, _, g1gen, _ := curve.Generators()
	vk.Sy = make([]curve.G1Affine, 3)
	vk.Sy[0] = g1gen
	vk.Sy[1] = g1gen
	vk.Sy[2] = g1gen
	vk.Sx = make([]curve.G1Affine, 3)
	vk.Sx[0] = g1gen
	vk.Sx[1] = g1gen
	vk.Sx[2] = g1gen
	vk.Q = make([]curve.G1Affine, 5)
	vk.Q[0] = g1gen
	vk.Q[1] = g1gen
	vk.Q[2] = g1gen
	vk.Q[3] = g1gen
	vk.Q[4] = g1gen
	vk.NbPublicVariables = 8000

	// random pk
	var pk ProvingKey
	pk.Vk = &vk
	pk.Domain[0] = *fft.NewDomain(42)
	pk.Domain[1] = *fft.NewDomain(8 * 42)
	pk.Q = make([][]fr.Element, 5)
	pk.Q[0] = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Q[1] = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Q[2] = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Q[3] = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Q[4] = make([]fr.Element, pk.Domain[0].Cardinality)

	for i := 0; i < 12; i++ {
		pk.Q[0][i].SetOne().Neg(&pk.Q[0][i])
		pk.Q[1][i].SetOne()
		pk.Q[3][i].SetUint64(42)
	}

	pk.PermutationY = make([]int64, 3*globalDomain[0].Cardinality)
	pk.PermutationX = make([]int64, 3*pk.Domain[0].Cardinality)
	pk.PermutationY[0] = -12
	pk.PermutationX[0] = -11
	pk.PermutationY[len(pk.PermutationY)-1] = 8888
	pk.PermutationX[len(pk.PermutationX)-1] = 8889

	var buf bytes.Buffer
	written, err := pk.WriteTo(&buf)
	if err != nil {
		t.Fatal("coudln't serialize", err)
	}

	var reconstructed ProvingKey

	read, err := reconstructed.ReadFrom(&buf)
	if err != nil {
		t.Fatal("coudln't deserialize", err)
	}

	if !reflect.DeepEqual(&pk, &reconstructed) {
		t.Fatal("reconstructed object don't match original")
	}

	if written != read {
		t.Fatal("bytes written / read don't match")
	}
}

func TestVerifyingKeySerialization(t *testing.T) {
	// create a random vk
	var vk VerifyingKey
	vk.SizeY = 10
	vk.SizeYInv.SetOne()
	vk.SizeX = 42
	vk.SizeXInv = fr.One()
	vk.SizeXInv.Add(&vk.SizeXInv, &vk.SizeXInv)

	_, _, g1gen, _ := curve.Generators()
	vk.Sy = make([]curve.G1Affine, 3)
	vk.Sy[0] = g1gen
	vk.Sy[1] = g1gen
	vk.Sy[2] = g1gen
	vk.Sx = make([]curve.G1Affine, 3)
	vk.Sx[0] = g1gen
	vk.Sx[1] = g1gen
	vk.Sx[2] = g1gen
	vk.Q = make([]curve.G1Affine, 5)
	vk.Q[0] = g1gen
	vk.Q[1] = g1gen
	vk.Q[2] = g1gen
	vk.Q[3] = g1gen
	vk.Q[4] = g1gen

	var buf bytes.Buffer
	written, err := vk.WriteTo(&buf)
	if err != nil {
		t.Fatal("coudln't serialize", err)
	}

	var reconstructed VerifyingKey

	read, err := reconstructed.ReadFrom(&buf)
	if err != nil {
		t.Fatal("coudln't deserialize", err)
	}

	if !reflect.DeepEqual(&vk, &reconstructed) {
		t.Fatal("reconstructed object don't match original")
	}

	if written != read {
		t.Fatal("bytes written / read don't match")
	}
}
