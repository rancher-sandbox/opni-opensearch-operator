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
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/rancher/opni-opensearch-operator/api/v1beta1"
	"github.com/rancher/opni-opensearch-operator/pkg/pki"
	"github.com/rancher/opni-opensearch-operator/pkg/resources"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	ErrEmptyPodList = errors.New("no pods found")
)

type Reconciler struct {
	opensearchCluster *v1beta1.OpensearchCluster
	client            client.Client
	ctx               context.Context
	transportCA       *tls.Certificate
	restCA            *tls.Certificate
	recreateCerts     bool
}

func NewReconciler(ctx context.Context, client client.Client, recreateCerts bool, cluster *v1beta1.OpensearchCluster) *Reconciler {
	return &Reconciler{
		client:            client,
		ctx:               ctx,
		opensearchCluster: cluster,
		recreateCerts:     recreateCerts,
	}
}

func (c *Reconciler) setTransportCA(caPEM []byte, caKeyPEM []byte) (err error) {
	ca, err := tls.X509KeyPair(caPEM, caKeyPEM)
	if err != nil {
		return err
	}
	c.transportCA = &ca
	return
}

func (c *Reconciler) setRESTCA(caPEM []byte, caKeyPEM []byte) (err error) {
	ca, err := tls.X509KeyPair(caPEM, caKeyPEM)
	if err != nil {
		return err
	}
	c.restCA = &ca
	return
}

func (c *Reconciler) maybeUpdateTransportCA() (ca []byte, key []byte, err error) {
	ca, key, err = pki.RetrieveCert(pki.TransportCASecretField, pki.TransportCAKeySecretField, c.opensearchCluster.Name, c.opensearchCluster.Namespace, c.client)
	if k8serrors.IsNotFound(err) || (pki.IsSecretDataMissing(err) && c.recreateCerts) {
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

func (c *Reconciler) createSANExtension(podName string, serviceName string, podIP net.IP) (pkix.Extension, error) {
	// We have to add RID Name for the Transport certs
	// The oid is 1.2.3.4.5.5.  0x88 is the Tag and Class for RID, 0x5 is the length
	// 0x2A is OID standard for the first two numbers - 40 * 1 + 2
	// https://www.alvestrand.no/objectid/2.5.29.17.html for details
	rawValues := []asn1.RawValue{
		{FullBytes: []byte{0x88, 0x05, 0x2A, 0x03, 0x04, 0x05, 0x05}},
	}
	// Because we're manually adding the SAN extention we need to manually marshall the DNS names
	dnsNames := []string{
		fmt.Sprintf("%s.%s", serviceName, c.opensearchCluster.Namespace),
		fmt.Sprintf("%s.%s.%s", podName, serviceName, c.opensearchCluster.Namespace),
		fmt.Sprintf("%s.%s.svc", serviceName, c.opensearchCluster.Namespace),
		fmt.Sprintf("%s.%s.%s.svc", podName, serviceName, c.opensearchCluster.Namespace),
		fmt.Sprintf("%s.%s.svc.cluster.local", serviceName, c.opensearchCluster.Namespace),
		fmt.Sprintf("%s.%s.%s.svc.cluster.local", podName, serviceName, c.opensearchCluster.Namespace),
	}
	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(name)})
	}

	ip := podIP.To4()
	if ip == nil {
		ip = podIP
	}
	rawValues = append(rawValues, asn1.RawValue{Tag: 7, Class: 2, Bytes: ip})

	rawByte, err := asn1.Marshal(rawValues)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       pki.SANExtensionID,
		Critical: true,
		Value:    rawByte,
	}, nil
}

func (c *CertsReconciler) createTransportCert(san pkix.Extension) (cert []byte, key []byte, err error) {

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
			san,
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

func (c *Reconciler) createRESTCert() (cert []byte, key []byte, err error) {
	rawValues := []asn1.RawValue{}
	dnsNames := []string{
		fmt.Sprintf("%s-%s.%s", c.opensearchCluster.Name, "os-client", c.opensearchCluster.Namespace),
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
				Id:       pki.SANExtensionID,
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

func (c *Reconciler) maybeUpdateTransportCert(podName string, serviceName string, podIP net.IP) (cert []byte, key []byte, err error) {
	lg := log.FromContext(c.ctx)
	sanExtension, err := c.createSANExtension(podName, serviceName, podIP)
	if err != nil {
		return
	}
	cert, key, err = pki.RetrieveCert(
		fmt.Sprintf("%s.crt", podName),
		fmt.Sprintf("%s.key", podName),
		c.opensearchCluster.Name,
		c.opensearchCluster.Namespace,
		c.client,
	)
	if k8serrors.IsNotFound(err) || pki.IsSecretDataMissing(err) {
		cert, key, err = c.createTransportCert(sanExtension)
	}
	if err != nil {
		return
	}
	certBlock, _ := pem.Decode(cert)
	if !pki.CertValidWithSANs(certBlock.Bytes, sanExtension) {
		lg.V(1).Info("cert not valid so recreating")
		cert, key, err = c.createTransportCert(sanExtension)
	}
	return
}

func (c *Reconciler) maybeUpdateRESTCert() (cert []byte, key []byte, err error) {
	cert, key, err = pki.RetrieveCert(pki.RESTCertField, pki.RESTKeyField, c.opensearchCluster.Name, c.opensearchCluster.Namespace, c.client)
	if k8serrors.IsNotFound(err) || (pki.IsSecretDataMissing(err) && c.recreateCerts) {
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

func (c *Reconciler) maybeUpdateRESTCA() (ca []byte, key []byte, err error) {
	ca, key, err = pki.RetrieveCert(pki.RESTCASecretField, pki.RESTCAKeySecretField, c.opensearchCluster.Name, c.opensearchCluster.Namespace, c.client)
	if k8serrors.IsNotFound(err) || (pki.IsSecretDataMissing(err) && c.recreateCerts) {
		ca, key, err = pki.CreateCA("Opensearch HTTP CA")
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

func (c *Reconciler) CertSecrets() (resourceList []resources.Resource, err error) {
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
	secretPKI.Data[pki.TransportCASecretField] = transportCA
	secretCerts.Data[pki.TransportCASecretField] = transportCA
	secretPKI.Data[pki.TransportCAKeySecretField] = transportCAKey

	// Update node certs for master nodes
	podList := &corev1.PodList{}
	err = c.client.List(c.ctx, podList, client.MatchingLabels(
		resources.CombineLabels(resources.NewOpensearchLabels(), resources.GenericLabels(c.opensearchCluster.Name)),
	))
	if err != nil {
		return
	}
	for _, pod := range podList.Items {
		ip := net.ParseIP(pod.Status.PodIP)
		if ip != nil {
			transportCert, transportKey, err := c.maybeUpdateTransportCert(pod.Name, fmt.Sprintf("%s-os-discovery", c.opensearchCluster.Name), ip)
			if err != nil {
				return resourceList, err
			}
			secretPKI.Data[fmt.Sprintf("%s.crt", pod.Name)] = transportCert
			secretCerts.Data[fmt.Sprintf("%s.crt", pod.Name)] = transportCert
			secretPKI.Data[fmt.Sprintf("%s.key", pod.Name)] = transportKey
			secretCerts.Data[fmt.Sprintf("%s.key", pod.Name)] = transportKey
		}
	}

	restCA, restCAKey, err := c.maybeUpdateRESTCA()
	if err != nil {
		return
	}
	secretPKI.Data[pki.RESTCASecretField] = restCA
	secretCerts.Data[pki.RESTCASecretField] = restCA
	secretPKI.Data[pki.RESTCAKeySecretField] = restCAKey

	restCert, restKey, err := c.maybeUpdateRESTCert()
	if err != nil {
		return
	}
	secretPKI.Data[pki.RESTCertField] = restCert
	secretCerts.Data[pki.RESTCertField] = restCert
	secretPKI.Data[pki.RESTKeyField] = restKey
	secretCerts.Data[pki.RESTKeyField] = restKey

	//ctrl.SetControllerReference(c.opensearchCluster, secret, c.client.Scheme())
	resourceList = append(resourceList, resources.Present(secretPKI))
	resourceList = append(resourceList, resources.Present(secretCerts))
	return
}

func IsEmptyPodList(err error) bool {
	return err == ErrEmptyPodList
}
