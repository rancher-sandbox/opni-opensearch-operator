package dashboards

import (
	"fmt"

	"github.com/rancher/opni-opensearch-operator/api/v1beta1"
	"github.com/rancher/opni-opensearch-operator/pkg/resources"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	dashboardsPort = corev1.ServicePort{
		Name:       "kibana",
		Port:       5601,
		TargetPort: intstr.FromInt(5601),
	}
)

func (r *Reconciler) dashboardsServices() []resources.Resource {
	labels := resources.NewOpensearchLabels()
	dashboardsSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", r.dashboards.Name, OpensearchDashboardsSuffix),
			Namespace: r.dashboards.Namespace,
			Labels:    labels.WithRole(v1beta1.OpensearchDashboardsRole),
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				dashboardsPort,
			},
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"role": string(v1beta1.OpensearchDashboardsRole),
			},
		},
	}

	ctrl.SetControllerReference(r.dashboards, dashboardsSvc, r.client.Scheme())

	return []resources.Resource{
		resources.Present(dashboardsSvc),
	}
}
