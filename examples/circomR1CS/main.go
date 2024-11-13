package main

import (
	"fmt"
	"log"
	"math/rand/v2"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/piano"
	"github.com/consensys/gnark/frontend"
	"github.com/sunblaze-ucb/simpleMPI/mpi"
)

const NUM_TXS = 2

func main() {
	dir, _ := os.Getwd()
	fmt.Println("working directory: ", dir)
	ccs, err := ReadR1CS("/home/pengfei/DeSNARK_R1CS/snark/data/circuit.r1cs", NUM_TXS)
	if err != nil {
		panic(err)
	}
	a, b, c := ccs.GetNbVariables()
	fmt.Println(a, b, c)

	{
		// Witnesses instantiation. Witness is known only by the prover,
		// while public w is a public data known by the verifier.
		var w R1CSCircuit
		for j := 0; j < NUM_TXS; j++ {
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

		// public data consists the polynomials describing the constants involved
		// in the constraints, the polynomial describing the permutation ("grand
		// product argument"), and the FFT domains.
		pk, vk, err := piano.Setup(ccs, witnessPublic)
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
}
