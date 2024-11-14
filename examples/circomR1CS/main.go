package main

import (
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/piano"
	"github.com/consensys/gnark/frontend"
	"github.com/sunblaze-ucb/simpleMPI/mpi"
)

func main() {
	num_txs, err := strconv.Atoi(os.Args[1])
	dir, _ := os.Getwd()
	fmt.Println("working directory: ", dir)
	ccs, err := ReadR1CS("/home/pengfei/DeSNARK_R1CS/snark/data/circuit.r1cs", num_txs)
	if err != nil {
		panic(err)
	}
	a, b, c := ccs.GetNbVariables()
	fmt.Println(a, b, c)

	{
		// Witnesses instantiation. Witness is known only by the prover,
		// while public w is a public data known by the verifier.
		var w R1CSCircuit
		for j := 0; j < num_txs; j++ {
			witnessIdx := rand.IntN(128)
			witness := ReadWitness(fmt.Sprintf("/home/pengfei/DeSNARK_R1CS/snark/data/witness.%d.json", witnessIdx))
			for i := 0; i < len(witness); i++ {
				w.Witness = append(w.Witness, frontend.Variable(witness[i]))
			}
		}

		witnessFull, err := frontend.NewWitness(&w, ecc.BN254)
		if err != nil {
			log.Fatal(err)
		}

		witnessPublic, err := frontend.NewWitness(&w, ecc.BN254, frontend.PublicOnly())
		if err != nil {
			log.Fatal(err)
		}

		repetitions := 3

		// public data consists the polynomials describing the constants involved
		// in the constraints, the polynomial describing the permutation ("grand
		// product argument"), and the FFT domains.
		pk, vk, err := piano.Setup(ccs, witnessPublic)
		if err != nil {
			log.Fatal(err)
		}

		// for i := 0; i < repetitions-1; i++ {
		// 	_, _, err := piano.Setup(ccs, witnessPublic)
		// 	if err != nil {
		// 		log.Fatal(err)
		// 	}
		// }

		proof, err := piano.Prove(ccs, pk, witnessFull)
		// for i := 0; i < repetitions-1; i++ {
		// 	_, err := piano.Prove(ccs, pk, witnessFull)
		// 	if err != nil {
		// 		log.Fatal(err)
		// 	}
		// }

		if err != nil {
			log.Fatal(err)
		}
		if mpi.SelfRank == 0 {
			start := time.Now()
			for i := 0; i < 10; i++ {
				err = piano.Verify(proof, vk, witnessPublic)
				if err != nil {
					log.Fatal(err)
				}
			}
			fmt.Printf("verify for %d variables: %d\n", num_txs, int(time.Since(start).Microseconds())/(10))
		}
	}
}
