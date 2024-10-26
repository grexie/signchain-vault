package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

func certTemplate() (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	if serialNumber, err := rand.Int(rand.Reader, serialNumberLimit); err != nil {
		return nil, errors.New("failed to generate serial number: " + err.Error())
	} else {

		tmpl := x509.Certificate{
			SerialNumber:          serialNumber,
			Subject:							 pkix.Name{CommonName: "Signchain Vault Certificate"},
			SignatureAlgorithm:    x509.SHA256WithRSA,
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour * 24 * 28),
			BasicConstraintsValid: true,
		}

		return &tmpl, nil
	}
}

func createCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}) (*x509.Certificate, []byte, error) {
	if certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv); err != nil {
		return nil, nil, err
	} else if cert, err := x509.ParseCertificate(certDER); err != nil {
		return nil, nil, err
	} else {
		b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
		certBytes := pem.EncodeToMemory(&b)
		return cert, certBytes, nil
	}
}

func CreateServerCert() (tls.Certificate, error) {
	if rootKey, err := rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return tls.Certificate{}, err
	} else if rootCertTmpl, err := certTemplate(); err != nil {
		return tls.Certificate{}, fmt.Errorf("creating cert template: %v", err)
	} else {
		rootCertTmpl.IsCA = true
		rootCertTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
		rootCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

		if rootCert, _, err := createCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey); err != nil {
			return tls.Certificate{}, fmt.Errorf("error creating cert: %v", err)
		} else if servKey, err := rsa.GenerateKey(rand.Reader, 2048); err != nil {
			return tls.Certificate{}, fmt.Errorf("generating random key: %v", err)
		} else if servCertTmpl, err := certTemplate(); err != nil {
			return tls.Certificate{}, fmt.Errorf("creating cert template: %v", err)
		} else {
			servCertTmpl.KeyUsage = x509.KeyUsageDigitalSignature
			servCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

			if _, servCertPEM, err := createCert(servCertTmpl, rootCert, &servKey.PublicKey, rootKey); err != nil {
				return tls.Certificate{}, fmt.Errorf("error creating cert: %v", err)
			} else {
				servKeyPEM := pem.EncodeToMemory(&pem.Block{
					Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(servKey),
				})
				
				if servTLSCert, err := tls.X509KeyPair(servCertPEM, servKeyPEM); err != nil {
					return tls.Certificate{}, fmt.Errorf("invalid key pair: %v", err)
				} else {
					return servTLSCert, nil
				}
			}
		}
	}
}