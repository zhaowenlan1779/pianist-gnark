package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/sunblaze-ucb/simpleMPI/mpi"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/gpiano"
	"github.com/consensys/gnark/frontend"
)

func main() {
	num_txs, err := strconv.Atoi(os.Args[1])
	dir, _ := os.Getwd()
	fmt.Println("working directory: ", dir)
	ccs, err := ReadR1CS("/root/hekaton-system/polygon_0.r1cs", num_txs)
	if err != nil {
		panic(err)
	}
	a, b, c := ccs.GetNbVariables()
	fmt.Println(a, b, c)
	fmt.Println(ccs.GetNbConstraints())

	{
		// Witnesses instantiation. Witness is known only by the prover,
		// while public w is a public data known by the verifier.
		var w R1CSCircuit
		witness := ReadWitness("/root/hekaton-system/polygon_0.json")
		for j := 0; j < num_txs; j++ {
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

		// public data consists the polynomials describing the constants involved
		// in the constraints, the polynomial describing the permutation ("grand
		// product argument"), and the FFT domains.

		pk, vk, err := gpiano.Setup(ccs, witnessPublic)
		if err != nil {
			log.Fatal(err)
		}

		proof, err := gpiano.Prove(ccs, pk, witnessFull)
		if err != nil {
			log.Fatal(err)
		}
		if mpi.SelfRank == 0 {
			err = gpiano.Verify(proof, vk, witnessPublic)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}
