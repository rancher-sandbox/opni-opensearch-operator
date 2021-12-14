package certs

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
	"fmt"
	"math/big"
	"time"

	"github.com/rancher/opni-opensearch-operator/api/v1beta1"
	"github.com/rancher/opni-opensearch-operator/pkg/pki"
	"github.com/rancher/opni-opensearch-operator/pkg/resources"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	TransportCASecretField    = "transportca.crt"
	TransportCAKeySecretField = "transportca.key"
	RESTCASecretField         = "httpca.crt"
	RESTCAKeySecretField      = "httpca.key"
	TransportCertField        = "transport.crt"
	TransportKeyField         = "transport.key"
	RESTCertField             = "http.crt"
	RESTKeyField              = "http.key"
)

type CertsReconciler struct {
	opensearchCluster *v1beta1.OpensearchCluster
	client            client.Client
	ctx               context.Context
	transportCA       *tls.Certificate
	restCA            *tls.Certificate
	recreateCerts     bool
}

func NewCertsReconciler(ctx context.Context, client client.Client, recreateCerts bool, cluster *v1beta1.OpensearchCluster) *CertsReconciler {
	return &CertsReconciler{
		client:            client,
		ctx:               ctx,
		opensearchCluster: cluster,
		recreateCerts:     recreateCerts,
	}
}

func (c *CertsReconciler) setTransportCA(caPEM []byte, caKeyPEM []byte) (err error) {
	ca, err := tls.X509KeyPair(caPEM, caKeyPEM)
	if err != nil {
		return err
	}
	c.transportCA = &ca
	return
}

func (c *CertsReconciler) setRESTCA(caPEM []byte, caKeyPEM []byte) (err error) {
	ca, err := tls.X509KeyPair(caPEM, caKeyPEM)
	if err != nil {
		return err
	}
	c.restCA = &ca
	return
}

func (c *CertsReconciler) retrieveCert(
	certField string,
	keyField string,
) (
	cert []byte,
	key []byte,
	err error,
) {
	secret := &corev1.Secret{}

	err = c.client.Get(c.ctx, types.NamespacedName{
		Name:      fmt.Sprintf("%s-os-pki", c.opensearchCluster.Name),
		Namespace: c.opensearchCluster.Namespace,
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

func (c *CertsReconciler) maybeUpdateTransportCA() (ca []byte, key []byte, err error) {
	ca, key, err = c.retrieveCert(TransportCASecretField, TransportCAKeySecretField)
	if k8serrors.IsNotFound(err) || (IsSecretDataMissing(err) && c.recreateCerts) {
		ca, key, err = pki.CreateCA("Opensearch Transport CA")
	}
	if err != nil {
		return
	}
	err = c.setTransportCA(ca, key)
	if err != nil {
		return
	}

	return
}

func (c *CertsReconciler) createTransportCert() (cert []byte, key []byte, err error) {
	// We have to add RID Name for the Transport certs
	// The oid is 1.2.3.4.5.5.  0x88 is the Tag and Class for RID, 0x5 is the length
	// 0x2A is OID standard for the first two numbers - 40 * 1 + 2
	// https://www.alvestrand.no/objectid/2.5.29.17.html for details
	rawValues := []asn1.RawValue{
		{FullBytes: []byte{0x88, 0x05, 0x2A, 0x03, 0x04, 0x05, 0x05}},
	}
	// Because we're manually adding the SAN extention we need to manually marshall the DNS names
	dnsNames := []string{
		fmt.Sprintf("*.%s", c.opensearchCluster.Namespace),
		fmt.Sprintf("*.%s.svc", c.opensearchCluster.Namespace),
		fmt.Sprintf("*.%s.cluster.local", c.opensearchCluster.Namespace),
		fmt.Sprintf("*.%s.svc.cluster.local", c.opensearchCluster.Namespace),
	}
	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(name)})
	}

	rawByte, err := asn1.Marshal(rawValues)
	if err != nil {
		return
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return
	}

	transportCert := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"SUSE Rancher"},
			Country:      []string{"US"},
			Locality:     []string{"San Francisco"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 17},
				Critical: true,
				Value:    rawByte,
			},
		},
	}
	keypair, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}
	cert, err = pki.SignCertificate(c.transportCA, transportCert, &keypair.PublicKey)
	if err != nil {
		return
	}

	pkcs8key, err := x509.MarshalPKCS8PrivateKey(keypair)
	if err != nil {
		return
	}

	keyPEM := new(bytes.Buffer)
	err = pem.Encode(keyPEM, &pem.Block{
		Type:  pki.PKCS8KeyPEMType,
		Bytes: pkcs8key,
	})
	if err != nil {
		return
	}
	key = keyPEM.Bytes()

	return
}

func (c *CertsReconciler) createRESTCert() (cert []byte, key []byte, err error) {
	rawValues := []asn1.RawValue{}
	dnsNames := []string{
		fmt.Sprintf("*.%s", c.opensearchCluster.Namespace),
		fmt.Sprintf("*.%s.svc", c.opensearchCluster.Namespace),
		fmt.Sprintf("*.%s.cluster.local", c.opensearchCluster.Namespace),
		fmt.Sprintf("*.%s.svc.cluster.local", c.opensearchCluster.Namespace),
	}
	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(name)})
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return
	}

	rawByte, err := asn1.Marshal(rawValues)
	if err != nil {
		return
	}

	restCert := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"SUSE Rancher"},
			Country:      []string{"US"},
			Locality:     []string{"San Francisco"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 17},
				Critical: true,
				Value:    rawByte,
			},
		},
	}

	keypair, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}
	cert, err = pki.SignCertificate(c.restCA, restCert, &keypair.PublicKey)
	if err != nil {
		return
	}

	pkcs8key, err := x509.MarshalPKCS8PrivateKey(keypair)
	if err != nil {
		return
	}

	keyPEM := new(bytes.Buffer)
	err = pem.Encode(keyPEM, &pem.Block{
		Type:  pki.PKCS8KeyPEMType,
		Bytes: pkcs8key,
	})
	if err != nil {
		return
	}
	key = keyPEM.Bytes()

	return
}

func (c *CertsReconciler) maybeUpdateTransportCert() (cert []byte, key []byte, err error) {
	cert, key, err = c.retrieveCert(TransportCertField, TransportKeyField)
	if k8serrors.IsNotFound(err) || (IsSecretDataMissing(err) && c.recreateCerts) {
		cert, key, err = c.createTransportCert()
	}
	if err != nil {
		return
	}
	certBlock, _ := pem.Decode(cert)
	if pki.CertExpiring(certBlock.Bytes) {
		if c.recreateCerts {
			cert, key, err = c.createTransportCert()
		} else {
			err = pki.ErrCertExpiring
			return
		}
	}
	return
}

func (c *CertsReconciler) maybeUpdateRESTCert() (cert []byte, key []byte, err error) {
	cert, key, err = c.retrieveCert(RESTCertField, RESTKeyField)
	if k8serrors.IsNotFound(err) || (IsSecretDataMissing(err) && c.recreateCerts) {
		cert, key, err = c.createRESTCert()
	}
	if err != nil {
		return
	}
	certBlock, _ := pem.Decode(cert)
	if pki.CertExpiring(certBlock.Bytes) {
		if c.recreateCerts {
			cert, key, err = c.createRESTCert()
		} else {
			err = pki.ErrCertExpiring
			return
		}
	}
	return
}

func (c *CertsReconciler) maybeUpdateRESTCA() (ca []byte, key []byte, err error) {
	ca, key, err = c.retrieveCert(RESTCASecretField, RESTCAKeySecretField)
	if k8serrors.IsNotFound(err) || (IsSecretDataMissing(err) && c.recreateCerts) {
		ca, key, err = pki.CreateCA("Opensearch REST CA")
	}
	if err != nil {
		return
	}
	err = c.setRESTCA(ca, key)
	if err != nil {
		return
	}

	return
}

func (c *CertsReconciler) CertSecrets() (resourceList []resources.Resource, err error) {
	secretPKI := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-os-pki", c.opensearchCluster.Name),
			Namespace: c.opensearchCluster.Namespace,
		},
		Data: map[string][]byte{},
	}

	secretCerts := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-os-certs", c.opensearchCluster.Name),
			Namespace: c.opensearchCluster.Namespace,
		},
		Data: map[string][]byte{},
	}
	transportCA, transportCAKey, err := c.maybeUpdateTransportCA()
	if err != nil {
		return
	}
	secretPKI.Data[TransportCASecretField] = transportCA
	secretCerts.Data[TransportCASecretField] = transportCA
	secretPKI.Data[TransportCAKeySecretField] = transportCAKey

	transportCert, transportKey, err := c.maybeUpdateTransportCert()
	if err != nil {
		return
	}
	secretPKI.Data[TransportCertField] = transportCert
	secretCerts.Data[TransportCertField] = transportCert
	secretPKI.Data[TransportKeyField] = transportKey
	secretCerts.Data[TransportKeyField] = transportKey

	restCA, restCAKey, err := c.maybeUpdateRESTCA()
	if err != nil {
		return
	}
	secretPKI.Data[RESTCASecretField] = restCA
	secretCerts.Data[RESTCASecretField] = restCA
	secretPKI.Data[RESTCAKeySecretField] = restCAKey

	restCert, restKey, err := c.maybeUpdateRESTCert()
	if err != nil {
		return
	}
	secretPKI.Data[RESTCertField] = restCert
	secretCerts.Data[RESTCertField] = restCert
	secretPKI.Data[RESTKeyField] = restKey
	secretCerts.Data[RESTKeyField] = restKey

	//ctrl.SetControllerReference(c.opensearchCluster, secret, c.client.Scheme())
	resourceList = append(resourceList, resources.Present(secretPKI))
	resourceList = append(resourceList, resources.Present(secretCerts))
	return
}
