package main

import (
	"fmt"
	"log"
	"os"

	"github.com/sunblaze-ucb/simpleMPI/mpi"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/gpiano"
	"github.com/consensys/gnark/frontend"
)

func main() {
	dir, _ := os.Getwd()
	fmt.Println("working directory: ", dir)
	ccs, err := ReadR1CS("/home/pengfei/DeSNARK_R1CS/snark/data/circuit.r1cs")
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
		{
			witness := ReadWitness("/home/pengfei/DeSNARK_R1CS/snark/data/witness.json")
			w.Witness = make([]frontend.Variable, len(witness))
			for i := 0; i < len(witness); i++ {
				w.Witness[i] = frontend.Variable(witness[i])
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
