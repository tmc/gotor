// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/aes"
	"crypto/rsa"
)

func HybridDecrypt(priv *rsa.PrivateKey, d []byte) ([]byte, error) {
	// XXX this could probably be optimized a little

	res, err := priv.Decrypt(nil, d[0:128], nil)
	if err != nil {
		return nil, err
	}

	if len(res) < 86 {
		return res, nil
	}

	data1 := res[16:86]
	aesCipher, err := aes.NewCipher(res[0:16])
	if err != nil {
		return nil, err
	}

	res2 := make([]byte, len(d)-128)
	aesCipher.Encrypt(res2, d[128:len(d)])

	finalRes := make([]byte, len(data1)+len(res2))
	copy(finalRes, data1)
	copy(finalRes[len(data1):], res2)

	return finalRes, nil
}
