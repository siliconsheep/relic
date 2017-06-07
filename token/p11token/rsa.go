//
// Copyright (c) SAS Institute Inc.
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
//

package p11token

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/sassoftware/relic/lib/x509tools"
)

// Convert token RSA public key to *rsa.PublicKey
func (key *Key) toRsaKey() (crypto.PublicKey, error) {
	modulus := key.token.getAttribute(key.pub, pkcs11.CKA_MODULUS)
	exponent := key.token.getAttribute(key.pub, pkcs11.CKA_PUBLIC_EXPONENT)
	if len(modulus) == 0 || len(exponent) == 0 {
		return nil, errors.New("Unable to retrieve RSA public key")
	}
	n := new(big.Int).SetBytes([]byte(modulus))
	e := int(attrToInt(exponent))
	return &rsa.PublicKey{N: n, E: e}, nil
}

// Sign a digest using token RSA private key
func (key *Key) signRSA(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var mech *pkcs11.Mechanism
	if opts == nil || opts.HashFunc() == 0 {
		return nil, errors.New("Signer options are required")
	} else if _, ok := opts.(*rsa.PSSOptions); ok {
		return nil, errors.New("RSA-PSS not implemented")
	} else {
		var ok bool
		digest, ok = x509tools.MarshalDigest(opts.HashFunc(), digest)
		if !ok {
			return nil, errors.New("unsupported hash function")
		}
		mech = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
	}
	err := key.token.ctx.SignInit(key.token.sh, []*pkcs11.Mechanism{mech}, key.priv)
	if err != nil {
		return nil, err
	}
	return key.token.ctx.Sign(key.token.sh, digest)
}

// Generate RSA-specific public and private key attributes from a PrivateKey
func rsaImportAttrs(priv *rsa.PrivateKey) (pubAttrs, privAttrs []*pkcs11.Attribute, err error) {
	if len(priv.Primes) != 2 || priv.Precomputed.Dp == nil || priv.Precomputed.Dq == nil || priv.Precomputed.Qinv == nil {
		// multi-prime keys and keys without the precomputed values are rare
		// enough not to be interesting
		return nil, nil, errors.New("unsupported RSA key")
	}
	pubAttrs = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(priv.E)).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, priv.N.Bytes()),
	}
	privAttrs = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(priv.E)).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, priv.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE_EXPONENT, priv.D.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_1, priv.Primes[0].Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_2, priv.Primes[1].Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_1, priv.Precomputed.Dp.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_2, priv.Precomputed.Dq.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_COEFFICIENT, priv.Precomputed.Qinv.Bytes()),
	}
	return
}

// Generate RSA-specific public attributes to generate an RSA key in the token
func rsaGenerateAttrs(bits uint) ([]*pkcs11.Attribute, *pkcs11.Mechanism, error) {
	if bits < 1024 || bits > 4096 {
		return nil, nil, errors.New("unsupported number of bits")
	}
	pubExponent := []byte{1, 0, 1} // 65537
	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, bits),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, pubExponent),
	}
	mech := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)
	return attrs, mech, nil
}
