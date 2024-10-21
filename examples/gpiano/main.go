// Copyright 2020 ConsenSys AG
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

package main

import (
	"fmt"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/gpiano"
	"github.com/consensys/gnark/backend/witness"
	"github.com/sunblaze-ucb/simpleMPI/mpi"

	"github.com/consensys/gnark/backend"
	gpiano_bn254 "github.com/consensys/gnark/internal/backend/bn254/gpiano"
	witness_bn254 "github.com/consensys/gnark/internal/backend/bn254/witness"
)

// In this example we show how to use PLONK with KZG commitments. The circuit that is
// showed here is the same as in ../exponentiate.

func main() {
	nv := 16
	numPublicInput := 4

	// Correct data: the proof passes
	{
		pk, vk, witnesses, err := gpiano_bn254.SetupRandom(ecc.BN254, 1<<nv, numPublicInput)
		if err != nil {
			log.Fatal(err)
		}

		opt, err := backend.NewProverConfig()
		proof, err := gpiano_bn254.ProveDirect(pk, witnesses, witnesses[0][:numPublicInput], opt)
		if err != nil {
			log.Fatal(err)
		}

		if mpi.SelfRank == 0 {
			publicWitness := witness_bn254.New(witnesses[0][:numPublicInput])
			err = gpiano.Verify(proof, vk, &witness.Witness{
				Vector: &publicWitness,
			})
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	// Wrong data: the proof fails
	// {
	// 	// Witnesses instantiation. Witness is known only by the prover,
	// 	// while public w is a public data known by the verifier.
	// 	var w, pW Circuit
	// 	w.X = 12
	// 	w.E = 2
	// 	w.Y = 144

	// 	pW.X = 12
	// 	pW.E = 2
	// 	pW.Y = 144 + 1

	// 	witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}

	// 	witnessPublic, err := frontend.NewWitness(&pW, ecc.BN254, frontend.PublicOnly())
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}

	// 	// public data consists the polynomials describing the constants involved
	// 	// in the constraints, the polynomial describing the permutation ("grand
	// 	// product argument"), and the FFT domains.
	// 	pk, vk, err := gpiano.Setup(ccs, witnessPublic)
	// 	//_, err := gpiano.Setup(r1cs, kate, &publicWitness)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}

	// 	proof, err := gpiano.Prove(ccs, pk, witnessFull)
	// 	if err != nil {
	// 		fmt.Printf("Failed to generate correct proof: %v\n", err)
	// 	} else if mpi.SelfRank == 0 {
	// 		fmt.Println("Verifying proof...")
	// 		err = gpiano.Verify(proof, vk, witnessPublic)
	// 		if err == nil {
	// 			log.Fatal("Error: wrong proof is accepted")
	// 		}
	// 	}
	// }
	fmt.Println("Done")
}

// printVector prints a vector of fr.Element
func printVector(name string, v []fr.Element) {
	fmt.Printf("%s: ", name)
	for _, e := range v {
		fmt.Printf("%s ", e.String())
	}
	fmt.Println()
}
