package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

const (
	CertificatePEMType = "CERTIFICATE"
	RSAKeyPEMType      = "RSA PRIVATE KEY"
	PKCS8KeyPEMType    = "PRIVATE KEY"
)

func CreateCA(commonName string) (ca []byte, cakey []byte, err error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return
	}
	caCertTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"SUSE Rancher"},
			Country:      []string{"US"},
			Locality:     []string{"San Francisco"},
			CommonName:   commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return
	}

	caPEM := new(bytes.Buffer)
	caKeyPEM := new(bytes.Buffer)

	err = pem.Encode(caPEM, &pem.Block{
		Type:  CertificatePEMType,
		Bytes: caBytes,
	})
	if err != nil {
		return
	}

	err = pem.Encode(caKeyPEM, &pem.Block{
		Type:  RSAKeyPEMType,
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey),
	})
	if err != nil {
		return
	}

	return caPEM.Bytes(), caKeyPEM.Bytes(), nil
}

func CertExpiring(der []byte) bool {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return true
	}
	return cert.NotAfter.Before(time.Now().AddDate(0, 0, 10))
}

func SignCertificate(ca *tls.Certificate, cert *x509.Certificate, pubKey *rsa.PublicKey) (certPEM []byte, err error) {
	cacert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return
	}

	signed, err := x509.CreateCertificate(rand.Reader, cert, cacert, pubKey, ca.PrivateKey)
	if err != nil {
		return
	}

	certPEMBuffer := new(bytes.Buffer)
	err = pem.Encode(certPEMBuffer, &pem.Block{
		Type:  CertificatePEMType,
		Bytes: signed,
	})
	if err != nil {
		return
	}

	return certPEMBuffer.Bytes(), nil
}
