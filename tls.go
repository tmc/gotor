// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base32"
	"log"
	"math/big"
	"math/rand"
	"net"
	"strings"
	"time"
)

const SSLRecordSize = 16 * 1024

type TorTLS struct {
	ctx *Ctx

	LinkKey, IdKey, AuthKey             *rsa.PrivateKey
	LinkCert, IdCert, AuthCert          *x509.Certificate
	LinkCertDER, IdCertDER, AuthCertDER []byte
	Fingerprint                         Fingerprint
	Fingerprint256                      []byte
}

func NewTLSCtx(isClient bool, or *ORCtx) (*TorTLS, error) {
	log.Printf("Creating TLS context with isClient=%v\n", isClient)

	ttls := &TorTLS{}

	// Considering how important this piece of code is for resisting fingerprints, we just follow whatever Tor itself does

	if !isClient { // XXX simplify
		nickname1 := RandomHostname(8, 20, "www.", ".net")
		nickname2 := RandomHostname(8, 20, "www.", ".com")

		issued, _ := time.ParseDuration("-24h") // XXX check what tor does (some time ago, then a long-time cert)
		expires, _ := time.ParseDuration("24h") // XXX also, don't re-use for all certs

		tmpPk, err := GenerateRSAKeyWithExponent(1024, 65537)
		if err != nil {
			return nil, err
		}

		authPk, err := GenerateRSAKeyWithExponent(1024, 65537)
		if err != nil {
			return nil, err
		}

		identityPk := or.identityKey
		idcert := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: nickname2,
			},
			Issuer: pkix.Name{
				CommonName: nickname2,
			},
			SerialNumber: big.NewInt(rand.Int63()),
			NotBefore:    time.Now().Add(issued),
			NotAfter:     time.Now().Add(expires),
			PublicKey:    identityPk.Public(),
		}
		authcert := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: nickname2,
			},
			Issuer: pkix.Name{
				CommonName: nickname2,
			},
			SerialNumber: big.NewInt(rand.Int63()),
			NotBefore:    time.Now().Add(issued),
			NotAfter:     time.Now().Add(expires),
			PublicKey:    authPk.Public(),
		}

		cert := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: nickname1,
			},
			Issuer: pkix.Name{
				CommonName: nickname2,
			},
			SerialNumber: big.NewInt(rand.Int63()),
			NotBefore:    time.Now().Add(issued),
			NotAfter:     time.Now().Add(expires),
			PublicKey:    tmpPk.Public(),
		}

		/*
			TODO: tmc replicate this
			if err := cert.Sign(identityPk, EVP_SHA1); err != nil {
				return nil, err
			}

			if err := idcert.Sign(identityPk, EVP_SHA1); err != nil {
				return nil, err
			}

			if err := authcert.Sign(identityPk, EVP_SHA1); err != nil {
				return nil, err
			}
		*/

		/*
			sslCtx.UseCertificate(cert)
			sslCtx.UsePrivateKey(tmpPk)

			sslCtx.SetEllipticCurve(Prime256v1)
		*/

		ttls.LinkCert = cert
		ttls.LinkKey = tmpPk
		ttls.LinkCertDER, err = x509.CreateCertificate(crand.Reader, cert, cert, tmpPk.Public(), tmpPk)
		if err != nil {
			return nil, err
		}

		ttls.IdCert = idcert
		ttls.IdKey = identityPk
		ttls.IdCertDER, err = x509.CreateCertificate(crand.Reader, idcert, idcert, identityPk.Public(), identityPk)
		if err != nil {
			return nil, err
		}

		keyAsn, err := asn1.Marshal(identityPk.PublicKey)
		if err != nil {
			return nil, err
		}
		fingerprint := sha1.Sum(keyAsn)
		log.Printf("Our fingerprint is %X\n", fingerprint)
		copy(ttls.Fingerprint[:], fingerprint[:])

		{
			sha := sha256.New()
			sha.Write(keyAsn)
			ttls.Fingerprint256 = sha.Sum(nil)
		}

		ttls.AuthCert = authcert
		ttls.AuthKey = authPk
		ttls.AuthCertDER, err = x509.CreateCertificate(crand.Reader, authcert, authcert, authPk.Public(), authPk)
		if err != nil {
			return nil, err
		}
	}

	/*
		// We don't want SSLv2 or SSLv3
		sslCtx.SetOptions(NoSSLv2 | NoSSLv3)

		// Prefer the server's ordering of ciphers: the client's ordering has
		// historically been chosen for fingerprinting resistance.
		sslCtx.SetOptions(CipherServerPreference)

		//XXX: panic() if we don't have openssl of 1.0.1e or later
		//XXX: please remember me why...

		// Tickets hurt perfect forward secrecy, but we still have non-server clients announce them, to reduce fingerprinting impact
		if !isClient {
			sslCtx.SetOptions(NoTicket)
		}

		// This saves us quite some memory
		//sslCtx.SetMode(ReleaseBuffers)

		// Avoid reusing DH keys if we don't have to
		sslCtx.SetOptions(SingleDHUse | SingleECDHUse)

		// Never renegotiate.
		sslCtx.SetOptions(NoSessionResumptionOrRenegotiation)

		// All compression does with encrypted data is waste CPU cycles. Disable it
		sslCtx.SetOptions(NoCompression)

		// Disable session caching
		sslCtx.SetSessionCacheMode(SessionCacheOff)

		// Allow all peer certificates
		sslCtx.SetVerify(VerifyNone, nil)
	*/

	return ttls, nil
}

func (or *ORCtx) GetTLSCtx(isClient bool) *TorTLS {
	or.tlsLock.Lock()
	defer or.tlsLock.Unlock()

	//assert(xxxxxxTlsCtx)
	if isClient {
		return or.clientTlsCtx
	} else {
		return or.serverTlsCtx
	}
}

func SetupTLS(or *ORCtx) error {
	var serverCtx, clientCtx *TorTLS

	serverCtx, err := NewTLSCtx(false, or)
	if err != nil {
		return err
	}

	if or.config.IsPublicServer {
		clientCtx = serverCtx
	} else {
		cCtx, err := NewTLSCtx(true, or)
		if err != nil {
			return err
		}
		clientCtx = cCtx
	}

	or.tlsLock.Lock()
	defer or.tlsLock.Unlock()

	or.clientTlsCtx = clientCtx
	or.serverTlsCtx = serverCtx

	return nil
}

func (or *ORCtx) WrapTLS(conn net.Conn, isClient bool) (*tls.Conn, *TorTLS, error) {
	return tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{or.serverTlsCtx.AuthCert.Raw},
				PrivateKey:  or.serverTlsCtx.AuthKey,
				Leaf:        or.serverTlsCtx.AuthCert,
			},
		},
		InsecureSkipVerify: true,
	}), or.GetTLSCtx(isClient), nil

	/*
		var tlsConn *Conn
		var err error
		if isClient {
			tlsConn, err = Client(conn, tls.ctx)
		} else {
			tlsConn, err = Server(conn, tls.ctx)
		}

		if err != nil {
			return nil, nil, err
		}

		return tlsConn, tls, nil
	*/
}

func RandomHostname(minLen, maxLen int, prefix, suffix string) string {
	chars := (rand.Int() % (maxLen - minLen)) + minLen

	enc := base32.StdEncoding
	rndChars := chars
	host := make([]byte, rndChars)
	CRandBytes(host)

	return prefix + strings.ToLower(enc.EncodeToString(host)[:chars]) + suffix
}
