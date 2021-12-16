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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type CertsReconciler struct {
	dashboards *v1beta1.Dashboards
	client     client.Client
	ctx        context.Context
	restCA     *tls.Certificate
}

func NewCertsReconciler(ctx context.Context, client client.Client, dashboards *v1beta1.Dashboards) *CertsReconciler {
	return &CertsReconciler{
		client:     client,
		ctx:        ctx,
		dashboards: dashboards,
	}
}

func (c *CertsReconciler) setRESTCA(caPEM []byte, caKeyPEM []byte) (err error) {
	ca, err := tls.X509KeyPair(caPEM, caKeyPEM)
	if err != nil {
		return err
	}
	c.restCA = &ca
	return
}

func (c *CertsReconciler) fetchAndSetRESTCA() (err error) {
	ca, key, err := pki.RetrieveCert(pki.RESTCASecretField, pki.RESTCAKeySecretField, c.dashboards.Spec.OpensearchCluster.Name, c.dashboards.Namespace, c.client)
	if err != nil {
		return
	}
	err = c.setRESTCA(ca, key)

	return
}

func (c *CertsReconciler) createRESTCert() (cert []byte, key []byte, err error) {
	rawValues := []asn1.RawValue{}
	dnsNames := []string{
		fmt.Sprintf("%s-%s.%s", c.dashboards.Name, resources.OpensearchDashboardsSuffix, c.dashboards.Namespace),
		fmt.Sprintf("%s-%s.%s.svc", c.dashboards.Name, resources.OpensearchDashboardsSuffix, c.dashboards.Namespace),
		fmt.Sprintf("%s-%s.%s.svc.cluster.local", c.dashboards.Name, resources.OpensearchDashboardsSuffix, c.dashboards.Namespace),
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

func (c *CertsReconciler) maybeUpdateRESTCert() (cert []byte, key []byte, err error) {
	tlsSecret := &corev1.Secret{}
	err = c.client.Get(c.ctx, types.NamespacedName{
		Name:      fmt.Sprintf("%s-osdb-tls", c.dashboards.Name),
		Namespace: c.dashboards.Namespace,
	}, tlsSecret)
	if k8serrors.IsNotFound(err) {
		cert, key, err = c.createRESTCert()
		return
	} else if err != nil {
		return
	}
	cert = tlsSecret.Data[corev1.TLSCertKey]
	key = tlsSecret.Data[corev1.TLSPrivateKeyKey]

	certBlock, _ := pem.Decode(cert)
	if pki.CertExpiring(certBlock.Bytes) {
		cert, key, err = c.createRESTCert()
	}
	return
}

func (c *CertsReconciler) CertSecret() resources.Resource {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-osdb-tls", c.dashboards.Name),
			Namespace: c.dashboards.Namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{},
	}
	if c.dashboards.Spec.TLSSecret != nil || c.dashboards.Spec.OpensearchCluster == nil {
		return resources.Absent(secret)
	}
	err := c.fetchAndSetRESTCA()
	if err != nil {
		return resources.Error(secret, err)
	}
	cert, key, err := c.maybeUpdateRESTCert()
	if err != nil {
		return resources.Error(secret, err)
	}
	secret.Data[corev1.TLSCertKey] = cert
	secret.Data[corev1.TLSPrivateKeyKey] = key

	err = ctrl.SetControllerReference(c.dashboards, secret, c.client.Scheme())

	return resources.Error(secret, err)
}
