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

// Code generated by gnark DO NOT EDIT

// Modifications Copyright 2023 Tianyi Liu and Tiancheng Xie

package gpiano

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/dkzg"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/consensys/gnark/internal/backend/bn254/cs"
	"github.com/consensys/gnark/logger"
	"github.com/sunblaze-ucb/simpleMPI/mpi"

	dkzgg "github.com/consensys/gnark-crypto/dkzg"
	bn254witness "github.com/consensys/gnark/internal/backend/bn254/witness"
)

var (
	globalDomain [2]*fft.Domain
	globalSRS    *kzg.SRS
)

// ProvingKey stores the data needed to generate a proof:
// * the commitment scheme
// * ql, prepended with as many ones as they are public inputs
// * qr, qm, qo prepended with as many zeroes as there are public inputs.
// * qk, prepended with as many zeroes as public inputs, to be completed by the prover
// with the list of public inputs.
// * sigma_1, sigma_2, sigma_3 in both basis
// * the copy constraint permutation
type ProvingKey struct {
	// Verifying Key is embedded into the proving key (needed by Prove)
	Vk *VerifyingKey

	// qr,ql,qm,qo (in canonical basis).
	Ql, Qr, Qm, Qo []fr.Element

	// qk in Lagrange basis (canonical basis), prepended with as many zeroes as public inputs.
	// Storing LQk in Lagrange basis saves a fft...
	Qk []fr.Element

	// Domains used for the FFTs.
	// Domain[0] = small Domain
	// Domain[1] = big Domain
	Domain [2]fft.Domain
	// Domain[0], Domain[1] fft.Domain

	// Permutation polynomials, indicate the index of sub-circuit for the next one.
	Sy1Canonical, Sy2Canonical, Sy3Canonical     []fr.Element
	// Permutation polynomials, indicate the specific row in some sub-circuit for the next one.
	Sx1Canonical, Sx2Canonical, Sx3Canonical     []fr.Element

	// position -> permuted position (position in [0,3*sizeSystem-1])
	PermutationY []int64
	PermutationX []int64
}

// VerifyingKey stores the data needed to verify a proof:
// * The commitment scheme
// * Commitments of ql prepended with as many ones as there are public inputs
// * Commitments of qr, qm, qo, qk prepended with as many zeroes as there are public inputs
// * Commitments to S1, S2, S3
type VerifyingKey struct {
	// Size circuit
	SizeY              uint64
	SizeX              uint64
	SizeYInv	       fr.Element
	SizeXInv		   fr.Element
	GeneratorY         fr.Element
	GeneratorX         fr.Element
	GeneratorXInv      fr.Element
	NbPublicVariables uint64

	// Commitment scheme that is used for an instantiation of PLONK
	DKZGSRS *dkzg.SRS
	KZGSRS  *kzg.SRS
	// cosetShift generator of the coset on the small domain
	CosetShift fr.Element

	// S commitments to S1, S2, S3
	Sy, Sx [3]kzg.Digest

	// Commitments to ql, qr, qm, qo prepended with as many zeroes (ones for l) as there are public inputs.
	// In particular Qk is not complete.
	Ql, Qr, Qm, Qo, Qk kzg.Digest
}

// Setup sets proving and verifying keys
func Setup(spr *cs.SparseR1CS, publicWitness bn254witness.Witness) (*ProvingKey, *VerifyingKey, error) {
	log := logger.Logger().With().Str("backend", "gpiano").Logger()
	globalDomain[0] = fft.NewDomain(mpi.WorldSize)
	if globalDomain[0].Cardinality != mpi.WorldSize {
		return nil, nil, fmt.Errorf("mpi.WorldSize is not a power of 2")
	}
	globalDomain[1] = fft.NewDomain(4 * mpi.WorldSize)

	var pk ProvingKey
	var vk VerifyingKey

	// The verifying key shares data with the proving key
	pk.Vk = &vk

	nbConstraints := len(spr.Constraints)

	// fft domains
	sizeSystem := int(nbConstraints + spr.NbPublicVariables) // spr.NbPublicVariables is for the placeholder constraints
	sizeSystem = (sizeSystem + int(mpi.WorldSize) - 1) / int(mpi.WorldSize)

	if sizeSystem < spr.NbPublicVariables {
		return nil, nil, fmt.Errorf("public variables not in a single sub-circuit")
	}

	pk.Domain[0] = *fft.NewDomain(uint64(sizeSystem))
	pk.Vk.CosetShift.Set(&pk.Domain[0].FrMultiplicativeGen)

	var t, s *big.Int
	var err error
	if mpi.SelfRank == 0 {
		var one fr.Element
		one.SetOne()
		for {
			t, err = rand.Int(rand.Reader, spr.CurveID().ScalarField())
			if err != nil {
				return nil, nil, err
			}
			var ele fr.Element
			ele.SetBigInt(t)
			if !ele.Exp(ele, big.NewInt(int64(globalDomain[0].Cardinality))).Equal(&one) {
				break
			}
		}
		for {
			s, err = rand.Int(rand.Reader, spr.CurveID().ScalarField())
			if err != nil {
				return nil, nil, err
			}
			var ele fr.Element
			ele.SetBigInt(s)
			if !ele.Exp(ele, big.NewInt(int64(pk.Domain[0].Cardinality))).Equal(&one) {
				break
			}
		}
		// send t and s to all other processes
		tByteLen := (t.BitLen() + 7) / 8
		sByteLen := (s.BitLen() + 7) / 8
		for i := uint64(1); i < mpi.WorldSize; i++ {
			if err := mpi.SendBytes([]byte{byte(tByteLen)}, i); err != nil {
				return nil, nil, err
			}
			if err := mpi.SendBytes(t.Bytes(), i); err != nil {
				return nil, nil, err
			}
			if err := mpi.SendBytes([]byte{byte(sByteLen)}, i); err != nil {
				return nil, nil, err
			}
			if err := mpi.SendBytes(s.Bytes(), i); err != nil {
				return nil, nil, err
			}
		}
		globalSRS, err = kzg.NewSRS(globalDomain[0].Cardinality, t)
		if err != nil {
			return nil, nil, err
		}
	} else {
		tByteLen, err := mpi.ReceiveBytes(1, 0)
		if err != nil {
			return nil, nil, err
		}
		tbytes, err := mpi.ReceiveBytes(uint64(tByteLen[0]), 0)
		if err != nil {
			return nil, nil, err
		}
		t = new(big.Int).SetBytes(tbytes)
		sByteLen, err := mpi.ReceiveBytes(1, 0)
		if err != nil {
			return nil, nil, err
		}
		sbytes, err := mpi.ReceiveBytes(uint64(sByteLen[0]), 0)
		if err != nil {
			return nil, nil, err
		}
		s = new(big.Int).SetBytes(sbytes)
	}
	vk.KZGSRS = globalSRS

	// h, the quotient polynomial is of degree 3(n+1)+2, so it's in a 3(n+2) dim vector space,
	// the domain is the next power of 2 superior to 3(n+2). 4*domainNum is enough in all cases
	// except when n<6.
	pk.Domain[1] = *fft.NewDomain(uint64(4 * sizeSystem))

	vk.SizeY = globalDomain[0].Cardinality
	vk.SizeYInv = globalDomain[0].CardinalityInv
	vk.SizeX = pk.Domain[0].Cardinality
	vk.SizeXInv = pk.Domain[0].CardinalityInv
	vk.GeneratorY.Set(&globalDomain[0].Generator)
	vk.GeneratorX.Set(&pk.Domain[0].Generator)
	vk.GeneratorXInv.Set(&pk.Domain[0].GeneratorInv)
	vk.NbPublicVariables = uint64(spr.NbPublicVariables)

	dkzgSRS, err := dkzg.NewSRS(vk.SizeX+3, []*big.Int{t, s}, &globalDomain[0].Generator)
	if err != nil {
		return nil, nil, err
	}
	if err := pk.InitKZG(dkzgSRS); err != nil {
		return nil, nil, err
	}

	// public polynomials corresponding to constraints: [ placholders | constraints | assertions ]
	pk.Ql = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Qr = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Qm = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Qo = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Qk = make([]fr.Element, pk.Domain[0].Cardinality)

	var offset int
	if mpi.SelfRank == 0 {
		for i := 0; i < spr.NbPublicVariables; i++ { // placeholders (-PUB_INPUT_i + qk_i = 0) TODO should return error is size is inconsistant
			pk.Ql[i].SetOne().Neg(&pk.Ql[i])
			pk.Qr[i].SetZero()
			pk.Qm[i].SetZero()
			pk.Qo[i].SetZero()
			pk.Qk[i].Set(&publicWitness[i])
		}
		offset = spr.NbPublicVariables
	} else {
		offset = 0
	}
	
	sizeSystem = int(pk.Domain[0].Cardinality)
	start := int(mpi.SelfRank) * sizeSystem + offset
	end := start - offset + sizeSystem
	if end > len(spr.Constraints) + spr.NbPublicVariables {
		end = len(spr.Constraints) + spr.NbPublicVariables
	}
	for i := start; i < end; i++ { // constraints
		j := i % sizeSystem
		ii := i - spr.NbPublicVariables
		pk.Ql[j].Set(&spr.Coefficients[spr.Constraints[ii].L.CoeffID()])
		pk.Qr[j].Set(&spr.Coefficients[spr.Constraints[ii].R.CoeffID()])
		pk.Qm[j].Set(&spr.Coefficients[spr.Constraints[ii].M[0].CoeffID()]).
			Mul(&pk.Qm[j], &spr.Coefficients[spr.Constraints[ii].M[1].CoeffID()])
		pk.Qo[j].Set(&spr.Coefficients[spr.Constraints[ii].O.CoeffID()])
		pk.Qk[j].Set(&spr.Coefficients[spr.Constraints[ii].K])
	}

	startTime := time.Now()

	pk.Domain[0].FFTInverse(pk.Ql, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Qr, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Qm, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Qo, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Qk, fft.DIF)
	fft.BitReverse(pk.Ql)
	fft.BitReverse(pk.Qr)
	fft.BitReverse(pk.Qm)
	fft.BitReverse(pk.Qo)
	fft.BitReverse(pk.Qk)

	// build permutation. Note: at this stage, the permutation takes in account the placeholders
	buildPermutation(spr, &pk)

	// set s1, s2, s3
	ccomputePermutationPolynomials(&pk)

	// Commit to the polynomials to set up the verifying key
	if vk.Ql, err = dkzg.Commit(pk.Ql, vk.DKZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Qr, err = dkzg.Commit(pk.Qr, vk.DKZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Qm, err = dkzg.Commit(pk.Qm, vk.DKZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Qo, err = dkzg.Commit(pk.Qo, vk.DKZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Qk, err = dkzg.Commit(pk.Qk, vk.DKZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Sy[0], err = dkzg.Commit(pk.Sy1Canonical, vk.DKZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Sy[1], err = dkzg.Commit(pk.Sy2Canonical, vk.DKZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Sy[2], err = dkzg.Commit(pk.Sy3Canonical, vk.DKZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Sx[0], err = dkzg.Commit(pk.Sx1Canonical, vk.DKZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Sx[1], err = dkzg.Commit(pk.Sx2Canonical, vk.DKZGSRS); err != nil {
		return nil, nil, err
	}
	if vk.Sx[2], err = dkzg.Commit(pk.Sx3Canonical, vk.DKZGSRS); err != nil {
		return nil, nil, err
	}

	log.Debug().Dur("took", time.Since(startTime)).Msg("setup (latter part) done")

	return &pk, &vk, nil
}

func SetupRandom(curveID ecc.ID, nbConstraints int, nbPublicInputs int) (*ProvingKey, *VerifyingKey, [][]fr.Element, error) {
	globalDomain[0] = fft.NewDomain(mpi.WorldSize)
	if globalDomain[0].Cardinality != mpi.WorldSize {
		return nil, nil, nil, fmt.Errorf("mpi.WorldSize is not a power of 2")
	}
	globalDomain[1] = fft.NewDomain(4 * mpi.WorldSize)

	var pk ProvingKey
	var vk VerifyingKey

	// The verifying key shares data with the proving key
	pk.Vk = &vk

	// fft domains
	sizeSystem := int(nbConstraints) // spr.NbPublicVariables is for the placeholder constraints
	sizeSystem = (sizeSystem + int(mpi.WorldSize) - 1) / int(mpi.WorldSize)

	pk.Domain[0] = *fft.NewDomain(uint64(sizeSystem))
	pk.Vk.CosetShift.Set(&pk.Domain[0].FrMultiplicativeGen)

	var t, s *big.Int
	var err error
	if mpi.SelfRank == 0 {
		var one fr.Element
		one.SetOne()
		for {
			t, err = rand.Int(rand.Reader, curveID.ScalarField())
			if err != nil {
				return nil, nil, nil, err
			}
			var ele fr.Element
			ele.SetBigInt(t)
			if !ele.Exp(ele, big.NewInt(int64(globalDomain[0].Cardinality))).Equal(&one) {
				break
			}
		}
		for {
			s, err = rand.Int(rand.Reader, curveID.ScalarField())
			if err != nil {
				return nil, nil, nil, err
			}
			var ele fr.Element
			ele.SetBigInt(s)
			if !ele.Exp(ele, big.NewInt(int64(pk.Domain[0].Cardinality))).Equal(&one) {
				break
			}
		}
		// send t and s to all other processes
		tByteLen := (t.BitLen() + 7) / 8
		sByteLen := (s.BitLen() + 7) / 8
		for i := uint64(1); i < mpi.WorldSize; i++ {
			if err := mpi.SendBytes([]byte{byte(tByteLen)}, i); err != nil {
				return nil, nil, nil, err
			}
			if err := mpi.SendBytes(t.Bytes(), i); err != nil {
				return nil, nil, nil, err
			}
			if err := mpi.SendBytes([]byte{byte(sByteLen)}, i); err != nil {
				return nil, nil, nil, err
			}
			if err := mpi.SendBytes(s.Bytes(), i); err != nil {
				return nil, nil, nil, err
			}
		}
		globalSRS, err = kzg.NewSRS(globalDomain[0].Cardinality, t)
		if err != nil {
			return nil, nil, nil, err
		}
	} else {
		tByteLen, err := mpi.ReceiveBytes(1, 0)
		if err != nil {
			return nil, nil, nil, err
		}
		tbytes, err := mpi.ReceiveBytes(uint64(tByteLen[0]), 0)
		if err != nil {
			return nil, nil, nil, err
		}
		t = new(big.Int).SetBytes(tbytes)
		sByteLen, err := mpi.ReceiveBytes(1, 0)
		if err != nil {
			return nil, nil, nil, err
		}
		sbytes, err := mpi.ReceiveBytes(uint64(sByteLen[0]), 0)
		if err != nil {
			return nil, nil, nil, err
		}
		s = new(big.Int).SetBytes(sbytes)
	}
	vk.KZGSRS = globalSRS

	// h, the quotient polynomial is of degree 3(n+1)+2, so it's in a 3(n+2) dim vector space,
	// the domain is the next power of 2 superior to 3(n+2). 4*domainNum is enough in all cases
	// except when n<6.
	pk.Domain[1] = *fft.NewDomain(uint64(4 * sizeSystem))

	vk.SizeY = globalDomain[0].Cardinality
	vk.SizeYInv = globalDomain[0].CardinalityInv
	vk.SizeX = pk.Domain[0].Cardinality
	vk.SizeXInv = pk.Domain[0].CardinalityInv
	vk.GeneratorY.Set(&globalDomain[0].Generator)
	vk.GeneratorX.Set(&pk.Domain[0].Generator)
	vk.GeneratorXInv.Set(&pk.Domain[0].GeneratorInv)
	vk.NbPublicVariables = uint64(nbPublicInputs)

	dkzgSRS, err := dkzg.NewSRS(vk.SizeX+3, []*big.Int{t, s}, &globalDomain[0].Generator)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := pk.InitKZG(dkzgSRS); err != nil {
		return nil, nil, nil, err
	}

	// public polynomials corresponding to constraints: [ placholders | constraints | assertions ]
	pk.Ql = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Qr = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Qm = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Qo = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Qk = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.PermutationX = make([]int64, 3 * pk.Domain[0].Cardinality)
	pk.PermutationY = make([]int64, 3 * pk.Domain[0].Cardinality)
	witnessesL := make([]fr.Element, pk.Domain[0].Cardinality)
	witnessesR := make([]fr.Element, pk.Domain[0].Cardinality)
	witnessesO := make([]fr.Element, pk.Domain[0].Cardinality)

	sizeSystem = int(pk.Domain[0].Cardinality)
	start := int(mpi.SelfRank) * sizeSystem
	end := start + sizeSystem
	if end > nbConstraints {
		end = nbConstraints
	}
	var prodL, prodR, prodM, prodO fr.Element
	for i := start; i < end; i++ { // constraints
		j := i % sizeSystem
		witnessesL[j].SetRandom()
		witnessesR[j].SetRandom()
		witnessesO[j].SetRandom()
		pk.Ql[j].SetRandom()
		pk.Qr[j].SetRandom()
		pk.Qm[j].SetRandom()
		pk.Qo[j].SetRandom()

		prodL.Mul(&pk.Ql[j], &witnessesL[j])
		prodR.Mul(&pk.Qr[j], &witnessesR[j])
		prodO.Mul(&pk.Qo[j], &witnessesO[j])
		prodM.Mul(&pk.Qm[j], &witnessesL[j]).Mul(&prodM, &witnessesR[j])
		pk.Qk[j].SetZero().Sub(&pk.Qk[j], &prodL).Sub(&pk.Qk[j], &prodR).Sub(&pk.Qk[j], &prodO).Sub(&pk.Qk[j], &prodM)	
	}

	for i := start; i < end; i++ {
		j := i % sizeSystem
		pk.PermutationX[j] = int64(j)
		pk.PermutationY[j] = int64(mpi.SelfRank)

		pk.PermutationX[j + sizeSystem] = int64(j + sizeSystem)
		pk.PermutationY[j + sizeSystem] = int64(mpi.SelfRank)

		pk.PermutationX[j + 2 * sizeSystem] = int64(j + 2 * sizeSystem)
		pk.PermutationY[j + 2 * sizeSystem] = int64(mpi.SelfRank)
	}

	pk.Domain[0].FFTInverse(pk.Ql, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Qr, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Qm, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Qo, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Qk, fft.DIF)
	fft.BitReverse(pk.Ql)
	fft.BitReverse(pk.Qr)
	fft.BitReverse(pk.Qm)
	fft.BitReverse(pk.Qo)
	fft.BitReverse(pk.Qk)

	// set s1, s2, s3
	ccomputePermutationPolynomials(&pk)

	// Commit to the polynomials to set up the verifying key
	if vk.Ql, err = dkzg.Commit(pk.Ql, vk.DKZGSRS); err != nil {
		return nil, nil, nil, err
	}
	if vk.Qr, err = dkzg.Commit(pk.Qr, vk.DKZGSRS); err != nil {
		return nil, nil, nil, err
	}
	if vk.Qm, err = dkzg.Commit(pk.Qm, vk.DKZGSRS); err != nil {
		return nil, nil, nil, err
	}
	if vk.Qo, err = dkzg.Commit(pk.Qo, vk.DKZGSRS); err != nil {
		return nil, nil, nil, err
	}
	if vk.Qk, err = dkzg.Commit(pk.Qk, vk.DKZGSRS); err != nil {
		return nil, nil, nil, err
	}
	if vk.Sy[0], err = dkzg.Commit(pk.Sy1Canonical, vk.DKZGSRS); err != nil {
		return nil, nil, nil, err
	}
	if vk.Sy[1], err = dkzg.Commit(pk.Sy2Canonical, vk.DKZGSRS); err != nil {
		return nil, nil, nil, err
	}
	if vk.Sy[2], err = dkzg.Commit(pk.Sy3Canonical, vk.DKZGSRS); err != nil {
		return nil, nil, nil, err
	}
	if vk.Sx[0], err = dkzg.Commit(pk.Sx1Canonical, vk.DKZGSRS); err != nil {
		return nil, nil, nil, err
	}
	if vk.Sx[1], err = dkzg.Commit(pk.Sx2Canonical, vk.DKZGSRS); err != nil {
		return nil, nil, nil, err
	}
	if vk.Sx[2], err = dkzg.Commit(pk.Sx3Canonical, vk.DKZGSRS); err != nil {
		return nil, nil, nil, err
	}

	return &pk, &vk, [][]fr.Element{witnessesL, witnessesR, witnessesO}, nil
}

// buildPermutation builds the Permutation associated with a circuit.
//
// The permutation s is composed of cycles of maximum length such that
//
// 			s. (l∥r∥o) = (l∥r∥o)
//
//, where l∥r∥o is the concatenation of the indices of l, r, o in
// ql.l+qr.r+qm.l.r+qo.O+k = 0.
//
// The permutation is encoded as a slice s of size 3*size(l), where the
// i-th entry of l∥r∥o is sent to the s[i]-th entry, so it acts on a tab
// like this: for i in tab: tab[i] = tab[permutation[i]]
func buildPermutation(spr *cs.SparseR1CS, pk *ProvingKey) {
	nbVariables := spr.NbInternalVariables + spr.NbPublicVariables + spr.NbSecretVariables
	size := pk.Domain[0].Cardinality
	totalSize := int(pk.Domain[0].Cardinality * mpi.WorldSize)

	// init permutation
	pk.PermutationY = make([]int64, 3*size)
	pk.PermutationX = make([]int64, 3*size)
	for i := 0; i < len(pk.PermutationY); i++ {
		pk.PermutationY[i] = -1
		pk.PermutationX[i] = -1
	}

	// init LRO position -> variable_ID
	lro := make([]int, 3*totalSize) // position -> variable_ID
	for i := 0; i < spr.NbPublicVariables; i++ {
		lro[i] = i // IDs of LRO associated to placeholders (only L needs to be taken care of)
	}

	offset := spr.NbPublicVariables
	for i := 0; i < len(spr.Constraints); i++ { // IDs of LRO associated to constraints
		lro[offset+i] = spr.Constraints[i].L.WireID()
		lro[totalSize+offset+i] = spr.Constraints[i].R.WireID()
		lro[2*totalSize+offset+i] = spr.Constraints[i].O.WireID()
	}

	// init cycle:
	// map ID -> last position the ID was seen
	cycle := make([]int64, nbVariables)
	for i := 0; i < len(cycle); i++ {
		cycle[i] = -1
	}

	// parse the wire ID
	parseID := func(id int64) (int64, int64) {
		v := id / int64(totalSize)
		r := id % int64(totalSize)
		y := r / int64(size)
		x := r % int64(size)
		return y, v * int64(size) + x
	}
	computeID := func(y, x int64) int64 {
		v := x / int64(size)
		r := x % int64(size)
		return v*int64(totalSize) + y*int64(size) + r
	}

	for i := 0; i < len(lro); i++ {
		if cycle[lro[i]] != -1 {
			// if != -1, it means we already encountered this value
			// so we need to set the corresponding permutation index.
			nY, nX := parseID(cycle[lro[i]])
			cY, cX := parseID(int64(i))
			if cY == int64(mpi.SelfRank) {
				pk.PermutationY[cX] = nY
				pk.PermutationX[cX] = nX
			}
		}
		cycle[lro[i]] = int64(i)
	}

	// complete the Permutation by filling the first IDs encountered
	for i := 0; i < len(pk.PermutationY); i++ {
		if pk.PermutationY[i] == -1 {
			j := computeID(int64(mpi.SelfRank), int64(i))
			pk.PermutationY[i], pk.PermutationX[i] = parseID(cycle[lro[j]])
		}
	}
}

// ccomputePermutationPolynomials computes the LDE (Lagrange basis) of the permutations
// s1, s2, s3.
//
// 1	z 	..	z**n-1	|	u	uz	..	u*z**n-1	|	u**2	u**2*z	..	u**2*z**n-1  |
//  																					 |
//        																				 | Permutation
// s11  s12 ..   s1n	   s21 s22 	 ..		s2n		     s31 	s32 	..		s3n		 v
// \---------------/       \--------------------/        \------------------------/
// 		s1 (LDE)                s2 (LDE)                          s3 (LDE)
func ccomputePermutationPolynomials(pk *ProvingKey) {

	n := int(pk.Domain[0].Cardinality)

	// Lagrange form of ID
	IDys := getIDySmallDomain(globalDomain[0])
	IDxs := getIDxSmallDomain(&pk.Domain[0])

	// Lagrange form of S1, S2, S3
	pk.Sy1Canonical = make([]fr.Element, n)
	pk.Sy2Canonical = make([]fr.Element, n)
	pk.Sy3Canonical = make([]fr.Element, n)
	pk.Sx1Canonical = make([]fr.Element, n)
	pk.Sx2Canonical = make([]fr.Element, n)
	pk.Sx3Canonical = make([]fr.Element, n)
	for i := 0; i < n; i++ {
		pk.Sy1Canonical[i].Set(&IDys[pk.PermutationY[i]])
		pk.Sy2Canonical[i].Set(&IDys[pk.PermutationY[n+i]])
		pk.Sy3Canonical[i].Set(&IDys[pk.PermutationY[2*n+i]])
		pk.Sx1Canonical[i].Set(&IDxs[pk.PermutationX[i]])
		pk.Sx2Canonical[i].Set(&IDxs[pk.PermutationX[n+i]])
		pk.Sx3Canonical[i].Set(&IDxs[pk.PermutationX[2*n+i]])
	}

	pk.Domain[0].FFTInverse(pk.Sy1Canonical, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Sy2Canonical, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Sy3Canonical, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Sx1Canonical, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Sx2Canonical, fft.DIF)
	pk.Domain[0].FFTInverse(pk.Sx3Canonical, fft.DIF)
	fft.BitReverse(pk.Sy1Canonical)
	fft.BitReverse(pk.Sy2Canonical)
	fft.BitReverse(pk.Sy3Canonical)
	fft.BitReverse(pk.Sx1Canonical)
	fft.BitReverse(pk.Sx2Canonical)
	fft.BitReverse(pk.Sx3Canonical)
}

// getIDxSmallDomain returns the Lagrange form of ID on the small domain
func getIDxSmallDomain(domain *fft.Domain) []fr.Element {

	res := make([]fr.Element, 3*domain.Cardinality)

	res[0].SetOne()
	res[domain.Cardinality].Set(&domain.FrMultiplicativeGen)
	res[2*domain.Cardinality].Square(&domain.FrMultiplicativeGen)

	for i := uint64(1); i < domain.Cardinality; i++ {
		res[i].Mul(&res[i-1], &domain.Generator)
		res[domain.Cardinality+i].Mul(&res[domain.Cardinality+i-1], &domain.Generator)
		res[2*domain.Cardinality+i].Mul(&res[2*domain.Cardinality+i-1], &domain.Generator)
	}

	return res
}

// getIDySmallDomain returns the Lagrange form of ID on the small domain
func getIDySmallDomain(domain *fft.Domain) []fr.Element {

	res := make([]fr.Element, domain.Cardinality)

	res[0].SetOne()
	for i := uint64(1); i < domain.Cardinality; i++ {
		res[i].Mul(&res[i-1], &domain.Generator)
	}

	return res
}

// InitKZG inits pk.Vk.KZG using pk.Domain[0] cardinality and provided SRS
//
// This should be used after deserializing a ProvingKey
// as pk.Vk.KZG is NOT serialized
func (pk *ProvingKey) InitKZG(srs dkzgg.SRS) error {
	return pk.Vk.InitKZG(srs)
}

// InitKZG inits vk.KZG using provided SRS
//
// This should be used after deserializing a VerifyingKey
// as vk.KZG is NOT serialized
//
// Note that this instantiate a new FFT domain using vk.Size
func (vk *VerifyingKey) InitKZG(srs dkzgg.SRS) error {
	_srs := srs.(*dkzg.SRS)

	if len(_srs.G1) < int(vk.SizeX) {
		return errors.New("dkzg srs is too small")
	}
	vk.DKZGSRS = _srs

	return nil
}

// NbPublicWitness returns the expected public witness size (number of field elements)
func (vk *VerifyingKey) NbPublicWitness() int {
	return int(vk.NbPublicVariables)
}

// VerifyingKey returns pk.Vk
func (pk *ProvingKey) VerifyingKey() interface{} {
	return pk.Vk
}
