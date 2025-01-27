package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func fillBenchBasesG1(samplePoints []bn254.G1Affine) {
	var r big.Int
	r.SetString("340444420969191673093399857471996460938405", 10)
	samplePoints[0].ScalarMultiplication(&samplePoints[0], &r)

	one := samplePoints[0].X
	one.SetOne()

	for i := 1; i < len(samplePoints); i++ {
		samplePoints[i].X.Add(&samplePoints[i-1].X, &one)
		samplePoints[i].Y.Sub(&samplePoints[i-1].Y, &one)
	}
}

func fillBenchScalars(sampleScalars []fr.Element) {
	// ensure every words of the scalars are filled
	for i := 1; i <= len(sampleScalars); i++ {
		t, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
		if err != nil {
			panic(err)
		}

		sampleScalars[i-1].SetBigInt(t)
	}
}

func BenchmarkMultiExp(b *testing.B) {
	var (
		samplePoints  [1 << 20]bn254.G1Affine
		sampleScalars [1 << 20]fr.Element
	)

	fillBenchScalars(sampleScalars[:])
	fillBenchBasesG1(samplePoints[:])

	var testPoint bn254.G1Affine

	for i := 5; i <= 20; i++ {
		using := 1 << i

		b.Run(fmt.Sprintf("%d points", using), func(b *testing.B) {
			b.ResetTimer()
			for j := 0; j < b.N; j++ {
				testPoint.MultiExp(samplePoints[:using], sampleScalars[:using], ecc.MultiExpConfig{ScalarsMont: true})
			}
		})
	}
}
