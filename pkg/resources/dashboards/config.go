package dashboards

import (
	"fmt"

	"github.com/rancher/opni-opensearch-operator/pkg/resources"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	defaultConfig = `server.host: "0"
opensearch.username: "kibanaserver"
opensearch.requestHeadersWhitelist: [ authorization,securitytenant ]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.certificate: /usr/share/opensearch-dashboards/tls/tls.crt
server.ssl.key: /usr/share/opensearch-dashboards/tls/tls.key
server.ssl.enabled: true
`
)

func (r *Reconciler) dashboardsConfigSecret() resources.Resource {
	secretName := fmt.Sprintf("%s-osdb-config", r.dashboards.Name)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: r.dashboards.Namespace,
		},
		StringData: map[string]string{
			"opensearch_dashboards.yml": defaultConfig,
		},
	}

	ctrl.SetControllerReference(r.dashboards, secret, r.client.Scheme())
	return resources.Present(secret)
}
