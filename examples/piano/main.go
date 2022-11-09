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

package main

import (
	"fmt"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/piano"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/backend/bn254/cs"
	"github.com/consensys/gnark/test"
	"github.com/sunblaze-ucb/simpleMPI/mpi"

	"github.com/consensys/gnark/frontend"
)

// In this example we show how to use PLONK with KZG commitments. The circuit that is
// showed here is the same as in ../exponentiate.

// Circuit y == x**e
// only the bitSize least significant bits of e are used
type Circuit struct {
	// tagging a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
// y == x**e
func (circuit *Circuit) Define(api frontend.API) error {

	api.AssertIsEqual(circuit.X, circuit.Y)
	return nil
}

func main() {

	var circuit Circuit

	// // building the circuit...
	ccs, err := frontend.Compile(ecc.BN254, scs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("circuit compilation error")
	}

	// create the necessary data for KZG.
	// This is a toy example, normally the trusted setup to build ZKG
	// has been ran before.
	// The size of the data in KZG should be the closest power of 2 bounding //
	// above max(nbConstraints, nbVariables).
	_r1cs := ccs.(*cs.SparseR1CS)
	dsrs, srs, err := test.NewKZGSRSPair(_r1cs)
	if err != nil {
		panic(err)
	}

	// Correct data: the proof passes
	{
		// Witnesses instantiation. Witness is known only by the prover,
		// while public w is a public data known by the verifier.
		var w Circuit
		w.X = 12
		w.Y = 12

		witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
		if err != nil {
			log.Fatal(err)
		}

		witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
		if err != nil {
			log.Fatal(err)
		}

		// public data consists the polynomials describing the constants involved
		// in the constraints, the polynomial describing the permutation ("grand
		// product argument"), and the FFT domains.
		pk, vk, err := piano.Setup(ccs, dsrs, srs, witnessPublic)
		//_, err := piano.Setup(r1cs, kate, &publicWitness)
		if err != nil {
			log.Fatal(err)
		}

		proof, err := piano.Prove(ccs, pk, witnessFull)
		if err != nil {
			log.Fatal(err)
		}

		if mpi.SelfRank == 0 {
			err = piano.Verify(proof, vk, witnessPublic)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	/*
		// Wrong data: the proof fails
		{
			// Witnesses instantiation. Witness is known only by the prover,
			// while public w is a public data known by the verifier.
			var w, pW Circuit
			w.X = 2
			w.Y = 4096

			pW.X = 3
			pW.Y = 4096

			witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
			if err != nil {
				log.Fatal(err)
			}

			witnessPublic, err := frontend.NewWitness(&pW, ecc.BN254, frontend.PublicOnly())
			if err != nil {
				log.Fatal(err)
			}

			// public data consists the polynomials describing the constants involved
			// in the constraints, the polynomial describing the permutation ("grand
			// product argument"), and the FFT domains.
			pk, vk, err := piano.Setup(ccs, dsrs, srs, witnessPublic)
			//_, err := piano.Setup(r1cs, kate, &publicWitness)
			if err != nil {
				log.Fatal(err)
			}

			proof, err := piano.Prove(ccs, pk, witnessFull)
			fmt.Println("Verifying proof...")
			if err != nil {
				log.Fatal(err)
			}

			if mpi.SelfRank == 0 {
				fmt.Println("Verifying proof...")
				err = piano.Verify(proof, vk, witnessPublic)
				if err == nil {
					log.Fatal("Error: wrong proof is accepted")
				}
			}
		}
	*/
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
