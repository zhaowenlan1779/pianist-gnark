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
	"bytes"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

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
	nv, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	numPublicInput := 4
	var repetitions int
	if nv <= 20 {
		repetitions = 10
	} else if nv <= 22 {
		repetitions = 5
	} else {
		repetitions = 3
	}

	// Correct data: the proof passes
	{
		start := time.Now()
		pk, vk, witnesses, err := gpiano_bn254.SetupRandom(ecc.BN254, 1<<nv, numPublicInput)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("send bytes %d, recv bytes %d\n", mpi.BytesSent, mpi.BytesReceived)
		fmt.Printf("preprocessing for %d variables: %d\n", nv, time.Since(start).Microseconds())

		opt, err := backend.NewProverConfig()
		start = time.Now()
		for i := 0; i < repetitions; i++ {
			_, err := gpiano_bn254.ProveDirect(pk, witnesses, witnesses[0][:numPublicInput], opt)
			if err != nil {
				log.Fatal(err)
			}
		}
		fmt.Printf("prove for %d variables: %d\n", nv, int(time.Since(start).Microseconds())/repetitions)

		bytesSentStart, bytesReceivedStart := mpi.BytesSent, mpi.BytesReceived
		proof, err := gpiano_bn254.ProveDirect(pk, witnesses, witnesses[0][:numPublicInput], opt)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("send bytes %d, recv bytes %d\n", mpi.BytesSent-bytesSentStart, mpi.BytesReceived-bytesReceivedStart)

		{
			var buf bytes.Buffer
			siz, err := proof.WriteTo(&buf)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("proof size compressed for %d variables: %d\n", nv, siz)
		}

		{
			var buf bytes.Buffer
			siz, err := proof.WriteRawTo(&buf)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("proof size uncompressed for %d variables: %d\n", nv, siz)
		}

		if mpi.SelfRank == 0 {
			publicWitness := witness_bn254.New(witnesses[0][:numPublicInput])
			start = time.Now()
			for i := 0; i < repetitions*10; i++ {
				err = gpiano.Verify(proof, vk, &witness.Witness{
					Vector: &publicWitness,
				})
				if err != nil {
					log.Fatal(err)
				}
			}
			fmt.Printf("verify for %d variables: %d\n", nv, int(time.Since(start).Microseconds())/(repetitions*10))
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
	mpi.Close()
}

// printVector prints a vector of fr.Element
func printVector(name string, v []fr.Element) {
	fmt.Printf("%s: ", name)
	for _, e := range v {
		fmt.Printf("%s ", e.String())
	}
	fmt.Println()
}
