package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	CertificatePEMType = "CERTIFICATE"
	RSAKeyPEMType      = "RSA PRIVATE KEY"
	PKCS8KeyPEMType    = "PRIVATE KEY"

	TransportCASecretField    = "transportca.crt"
	TransportCAKeySecretField = "transportca.key"
	RESTCASecretField         = "httpca.crt"
	RESTCAKeySecretField      = "httpca.key"
	TransportCertField        = "transport.crt"
	TransportKeyField         = "transport.key"
	RESTCertField             = "http.crt"
	RESTKeyField              = "http.key"
)

var (
	SANExtensionID = asn1.ObjectIdentifier{2, 5, 29, 17}
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

func CertValidWithSANs(der []byte, sans pkix.Extension) bool {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return false
	}
	if cert.NotAfter.Before(time.Now().AddDate(0, 0, 10)) {
		return false
	}

	for _, ext := range cert.Extensions {
		if SANExtensionID.Equal(ext.Id) && bytes.Equal(sans.Value, ext.Value) {
			return true
		}
	}

	return false
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

func IsSecretDataMissing(err error) bool {
	return errors.Is(err, ErrSecretDataMissing)
}

func RetrieveCert(
	certField string,
	keyField string,
	opensearchName string,
	namespace string,
	client client.Client,
) (
	cert []byte,
	key []byte,
	err error,
) {
	secret := &corev1.Secret{}

	err = client.Get(context.Background(), types.NamespacedName{
		Name:      fmt.Sprintf("%s-os-pki", opensearchName),
		Namespace: namespace,
	}, secret)

	if err != nil {
		return
	}

	var certOK, keyOK bool
	cert, certOK = secret.Data[certField]
	key, keyOK = secret.Data[keyField]
	if !certOK || !keyOK {
		err = ErrSecretDataMissing
		return
	}
	return
}
