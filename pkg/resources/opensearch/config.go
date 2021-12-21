package opensearch

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/rancher/opni-opensearch-operator/pkg/resources"
	"github.com/rancher/opni/pkg/util"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	internalUsersKey          = "internal_users.yml"
	bcryptCost                = 5
	internalUsersSecretSuffix = "os-internalusers"

	PasswordSecretSuffix = "os-password"
)

var (
	defaultLoggingConfig = `appender:
  console:
    layout:
      conversionPattern: '[%d{ISO8601}][%-5p][%-25c] %m%n'
      type: consolePattern
    type: console
es.logger.level: INFO
logger:
  action: DEBUG
  com.amazonaws: WARN
rootLogger: ${es.logger.level}, console`

	internalUsersTemplate = template.Must(template.New("internalusers").Parse(`
_meta:
  type: "internalusers"
  config_version: 2
admin:
  hash: "{{ .AdminPassword }}"
  reserved: true
  backend_roles:
  - "admin"
  description: "Admin user"
kibanaserver:
  hash: "{{ .DashboardsPassword }}"
  reserved: true
  description: "Opensearch Dashboards user"
`))

	// TODO: investigate alternatives for storing this config.
	defaultConfig = `network.host: 0.0.0.0
plugins.security.ssl.transport.pemcert_filepath: certs/${HOSTNAME}.crt
plugins.security.ssl.transport.pemkey_filepath: certs/${HOSTNAME}.key
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/transportca.crt
plugins.security.ssl.transport.enforce_hostname_verification: true
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: certs/http.crt
plugins.security.ssl.http.pemkey_filepath: certs/http.key
plugins.security.ssl.http.pemtrustedcas_filepath: certs/httpca.crt
plugins.security.allow_unsafe_democertificates: false
plugins.security.allow_default_init_securityindex: true
plugins.security.audit.type: internal_opensearch
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opendistro-notifications-*", ".opendistro-notebooks", ".opendistro-asynchronous-search-response*", ".replication-metadata-store"]
node.max_local_storage_nodes: 3
`
)

func (r *Reconciler) opensearchConfigSecret() resources.Resource {
	secretName := fmt.Sprintf("%s-os-config", r.opensearchCluster.Name)
	if r.opensearchCluster.Spec.ConfigSecret != nil {
		// If auth secret is provided, use it instead of creating a new one. If
		// the secret doesn't exist, create one with the given name.
		secretName = r.opensearchCluster.Spec.ConfigSecret.Name
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: r.opensearchCluster.Namespace,
		},
		StringData: map[string]string{
			"logging.yml":    defaultLoggingConfig,
			"opensearch.yml": defaultConfig,
		},
	}

	ctrl.SetControllerReference(r.opensearchCluster, secret, r.client.Scheme())
	return resources.Present(secret)
}

func (r *Reconciler) internalUsersSecret() resources.Resource {
	internalUsersSecretName := fmt.Sprintf("%s-%s", r.opensearchCluster.Name, internalUsersSecretSuffix)
	lg := log.FromContext(r.ctx)

	if !r.generatePassword() {
		// Just get and return the existing secret
		secret := &corev1.Secret{}
		err := r.client.Get(r.ctx, types.NamespacedName{
			Name:      internalUsersSecretName,
			Namespace: r.opensearchCluster.Namespace,
		}, secret)
		return resources.Error(secret, err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      internalUsersSecretName,
			Namespace: r.opensearchCluster.Namespace,
		},
		Data: map[string][]byte{},
	}
	adminPassword, dashboardsPassword, err := r.opensearchPasswordSecret()
	if err != nil {
		return resources.Error(secret, err)

	}
	lg.V(1).Info("generating bcrypt hash of password; this is slow")
	ns := corev1.Namespace{}
	r.client.Get(r.ctx, types.NamespacedName{
		Name: r.opensearchCluster.Namespace,
	}, &ns)

	var (
		adminHash, dashboardsHash []byte
		costToUse                 int
		buffer                    bytes.Buffer
	)
	if value, ok := ns.Annotations["controller-test"]; ok && value == "true" {
		lg.V(1).Info("test namespace, using minimum bcrypt difficulty to hash password")
		costToUse = 4
	} else {
		costToUse = bcryptCost
	}

	adminHash, err = bcrypt.GenerateFromPassword(adminPassword, costToUse)
	if err != nil {
		return resources.Error(secret, err)
	}

	dashboardsHash, err = bcrypt.GenerateFromPassword(dashboardsPassword, costToUse)
	if err != nil {
		return resources.Error(secret, err)
	}

	passwords := struct {
		AdminPassword      string
		DashboardsPassword string
	}{
		AdminPassword:      string(adminHash),
		DashboardsPassword: string(dashboardsHash),
	}
	err = internalUsersTemplate.Execute(&buffer, passwords)
	if err != nil {
		return resources.Error(secret, err)
	}

	secret.Data[internalUsersKey] = buffer.Bytes()
	ctrl.SetControllerReference(r.opensearchCluster, secret, r.client.Scheme())
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := r.client.Get(r.ctx, client.ObjectKeyFromObject(r.opensearchCluster), r.opensearchCluster); err != nil {
			return err
		}
		r.opensearchCluster.Status.Auth.GenerateOpensearchHash = pointer.BoolPtr(false)
		return r.client.Status().Update(r.ctx, r.opensearchCluster)
	})
	return resources.Error(secret, err)
}

func (r *Reconciler) opensearchPasswordSecret() (adminPassword []byte, dashboardsPassword []byte, err error) {
	var (
		passwordSecretRef  *corev1.SecretKeySelector
		passwordSecretName = fmt.Sprintf("%s-%s", r.opensearchCluster.Name, PasswordSecretSuffix)
	)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      passwordSecretName,
			Namespace: r.opensearchCluster.Namespace,
		},
		Data: map[string][]byte{},
	}

	adminPassword, err = r.retriveOrGenerateAdminPassword()
	if err != nil {
		return
	}

	if r.opensearchCluster.Spec.AdminPasswordFrom == nil {
		secret.Data["admin"] = adminPassword
		passwordSecretRef = &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{
				Name: passwordSecretName,
			},
			Key: "admin",
		}
	} else {
		passwordSecretRef = r.opensearchCluster.Spec.AdminPasswordFrom
	}

	dashboardsPassword, err = r.retriveOrGenerateDashboardsPassword()
	if err != nil {
		return
	}
	secret.Data["dashboards"] = dashboardsPassword
	ctrl.SetControllerReference(r.opensearchCluster, secret, r.client.Scheme())
	err = util.CreateOrUpdate(r.ctx, r.client, secret)
	if err != nil {
		return
	}

	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := r.client.Get(r.ctx, client.ObjectKeyFromObject(r.opensearchCluster), r.opensearchCluster); err != nil {
			return err
		}
		r.opensearchCluster.Status.Auth.OpensearchAuthSecretKeyRef = passwordSecretRef
		return r.client.Status().Update(r.ctx, r.opensearchCluster)
	})
	return
}

func (r *Reconciler) retriveOrGenerateAdminPassword() (password []byte, err error) {
	var ok bool
	if r.opensearchCluster.Spec.AdminPasswordFrom != nil {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      r.opensearchCluster.Spec.AdminPasswordFrom.Name,
				Namespace: r.opensearchCluster.Namespace,
			},
		}
		err = r.client.Get(r.ctx, client.ObjectKeyFromObject(secret), secret)
		if err != nil {
			return
		}
		password, ok = secret.Data[r.opensearchCluster.Spec.AdminPasswordFrom.Key]
		if !ok {
			err = ErrSecretKeyNotExist(r.opensearchCluster.Spec.AdminPasswordFrom.Key, r.opensearchCluster.Spec.AdminPasswordFrom.Name)
		}
		return
	}

	if r.opensearchCluster.Status.Auth.OpensearchAuthSecretKeyRef != nil {
		existingSecret := corev1.Secret{}
		err = r.client.Get(r.ctx, types.NamespacedName{
			Name:      r.opensearchCluster.Status.Auth.OpensearchAuthSecretKeyRef.Name,
			Namespace: r.opensearchCluster.Namespace,
		}, &existingSecret)
		if err != nil {
			return
		}
		password, ok = existingSecret.Data[r.opensearchCluster.Status.Auth.OpensearchAuthSecretKeyRef.Key]
		if !ok {
			err = ErrSecretKeyNotExist(
				r.opensearchCluster.Status.Auth.OpensearchAuthSecretKeyRef.Key,
				r.opensearchCluster.Status.Auth.OpensearchAuthSecretKeyRef.Name,
			)
		}
		return
	}
	password = util.GenerateRandomPassword()
	return
}

func (r *Reconciler) retriveOrGenerateDashboardsPassword() (password []byte, err error) {
	var ok bool

	if r.opensearchCluster.Status.Auth.OpensearchAuthSecretKeyRef != nil {
		existingSecret := corev1.Secret{}
		err = r.client.Get(r.ctx, types.NamespacedName{
			Name:      fmt.Sprintf("%s-%s", r.opensearchCluster.Name, PasswordSecretSuffix),
			Namespace: r.opensearchCluster.Namespace,
		}, &existingSecret)
		if err != nil {
			return
		}
		password, ok = existingSecret.Data["dashboards"]
		if !ok {
			err = ErrSecretKeyNotExist("dashboards", fmt.Sprintf("%s-%s", r.opensearchCluster.Name, PasswordSecretSuffix))
		}
		return
	}
	password = util.GenerateRandomPassword()
	return
}

func (r *Reconciler) generatePassword() bool {
	return r.opensearchCluster.Status.Auth.GenerateOpensearchHash == nil || *r.opensearchCluster.Status.Auth.GenerateOpensearchHash
}
