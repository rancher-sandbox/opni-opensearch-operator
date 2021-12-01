package dashboards

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/rancher/opni-opensearch-operator/api/v1beta1"
	"github.com/rancher/opni-opensearch-operator/pkg/resources"
	"github.com/rancher/opni-opensearch-operator/pkg/resources/opensearch"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	OpensearchDashboardsSuffix = "os-dashboards"
)

var (
	ErrOpensearchURLInvalid = errors.New("opensearch URL is not a valid URL")
)

func (r *Reconciler) dashboardshWorkloads() []resources.Resource {
	return []resources.Resource{
		r.dashboardsWorkload(),
	}
}

func (r *Reconciler) dashboardsWorkload() resources.Resource {
	labels := resources.NewOpensearchLabels().
		WithRole(v1beta1.OpensearchDashboardsRole)

	imageSpec := r.dashboardsImageSpec()
	workload := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", r.dashboards.Name, OpensearchDashboardsSuffix),
			Namespace: r.dashboards.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: r.dashboards.Spec.Replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					Affinity: r.dashboards.Spec.Affinity,
					Containers: []corev1.Container{
						{
							Name:            "dashboards",
							Image:           imageSpec.GetImage(),
							ImagePullPolicy: imageSpec.GetImagePullPolicy(),
							ReadinessProbe: &corev1.Probe{
								FailureThreshold:    3,
								InitialDelaySeconds: 60,
								PeriodSeconds:       30,
								SuccessThreshold:    1,
								TimeoutSeconds:      10,
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/api/status",
										Port: intstr.FromInt(5601),
									},
								},
							},
							LivenessProbe: &corev1.Probe{
								FailureThreshold:    3,
								InitialDelaySeconds: 10,
								PeriodSeconds:       10,
								SuccessThreshold:    1,
								TimeoutSeconds:      1,
								Handler: corev1.Handler{
									TCPSocket: &corev1.TCPSocketAction{
										Port: intstr.FromInt(5601),
									},
								},
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "http",
									ContainerPort: 5601,
								},
							},
						},
					},
					ImagePullSecrets: imageSpec.ImagePullSecrets,
					NodeSelector:     r.dashboards.Spec.NodeSelector,
					Tolerations:      r.dashboards.Spec.Tolerations,
				},
			},
		},
	}
	env, err := r.dashboardsEnv()
	if err != nil {
		return resources.Error(workload, err)
	}
	workload.Spec.Template.Spec.Containers[0].Env = env
	if r.dashboards.Spec.Resources != nil {
		workload.Spec.Template.Spec.Containers[0].Resources =
			*r.dashboards.Spec.Resources
	}

	ctrl.SetControllerReference(r.dashboards, workload, r.client.Scheme())
	return resources.Present(workload)
}

func (r *Reconciler) dashboardsImageSpec() v1beta1.ImageSpec {
	return v1beta1.ImageResolver{
		Version:             r.dashboards.Spec.Version,
		ImageName:           "opensearch-dashboards",
		DefaultRepo:         "docker.io/opensearchproject",
		DefaultRepoOverride: r.dashboards.Spec.DefaultRepo,
		ImageOverride:       r.dashboards.Spec.Image,
	}.Resolve()
}

func (r *Reconciler) dashboardsEnv() (env []corev1.EnvVar, err error) {
	if r.dashboards.Spec.OpensearchCluster != nil {
		namespace := r.dashboards.Spec.OpensearchCluster.Namespace
		if namespace == "" {
			namespace = r.dashboards.Namespace
		}
		opensearchCluster := &v1beta1.OpensearchCluster{}
		err = r.client.Get(r.ctx, types.NamespacedName{
			Name:      r.dashboards.Spec.OpensearchCluster.Name,
			Namespace: namespace,
		}, opensearchCluster)
		if err != nil {
			return
		}
		env = append(env, corev1.EnvVar{
			Name:  "OPENSEARCH_HOSTS",
			Value: fmt.Sprintf("https://%s-%s.%s:9200", opensearchCluster.Name, opensearch.OpensearchClientSuffix, namespace),
		})
	} else {
		_, err = url.ParseRequestURI(r.dashboards.Spec.OpensearchURL)
		if err != nil {
			return env, ErrOpensearchURLInvalid
		}
		env = append(env, corev1.EnvVar{
			Name:  "OPENSEARCH_HOSTS",
			Value: r.dashboards.Spec.OpensearchURL,
		})
	}
	return
}
