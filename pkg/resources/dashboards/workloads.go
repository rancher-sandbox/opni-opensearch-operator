package dashboards

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/rancher/opni-opensearch-operator/api/v1beta1"
	"github.com/rancher/opni-opensearch-operator/pkg/pki"
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
										Path:   "/api/status",
										Port:   intstr.FromInt(5601),
										Scheme: corev1.URISchemeHTTPS,
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
									Name:          "https",
									ContainerPort: 5601,
								},
							},
							VolumeMounts: r.dashboardVolumeMounts(),
						},
					},
					ImagePullSecrets: imageSpec.ImagePullSecrets,
					NodeSelector:     r.dashboards.Spec.NodeSelector,
					Tolerations:      r.dashboards.Spec.Tolerations,
					Volumes:          r.dashboardVolumes(),
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
		opensearchCluster := &v1beta1.OpensearchCluster{}
		err = r.client.Get(r.ctx, types.NamespacedName{
			Name:      r.dashboards.Spec.OpensearchCluster.Name,
			Namespace: r.dashboards.Namespace,
		}, opensearchCluster)
		if err != nil {
			return
		}
		env = append(env, corev1.EnvVar{
			Name:  "OPENSEARCH_HOSTS",
			Value: fmt.Sprintf("https://%s-%s.%s:9200", opensearchCluster.Name, resources.OpensearchClientSuffix, r.dashboards.Namespace),
		})
		env = append(env, corev1.EnvVar{
			Name: "OPENSEARCH_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: fmt.Sprintf("%s-%s", r.dashboards.Spec.OpensearchCluster.Name, opensearch.PasswordSecretSuffix),
					},
					Key: "dashboards",
				},
			},
		})
		env = append(env, corev1.EnvVar{
			Name:  "OPENSEARCH_SSL_CERTIFICATEAUTHORITIES",
			Value: fmt.Sprintf("/usr/share/opensearch-dashboards/%s", pki.RESTCASecretField),
		})
	} else if r.dashboards.Spec.OpensearchConfig != nil {
		_, err = url.ParseRequestURI(r.dashboards.Spec.OpensearchConfig.URL)
		if err != nil {
			return env, ErrOpensearchURLInvalid
		}
		env = append(env, corev1.EnvVar{
			Name:  "OPENSEARCH_HOSTS",
			Value: r.dashboards.Spec.OpensearchConfig.URL,
		})
		if r.dashboards.Spec.OpensearchConfig.VerifySSL != nil && !*r.dashboards.Spec.OpensearchConfig.VerifySSL {
			env = append(env, corev1.EnvVar{
				Name:  "OPENSEARCH_SSL_VERIFICATIONMODE",
				Value: "none",
			})
		}
		if r.dashboards.Spec.OpensearchConfig.Username != "" {
			env = append(env, corev1.EnvVar{
				Name:  "OPENSEARCH_USERNAME",
				Value: r.dashboards.Spec.OpensearchConfig.Username,
			})
		}
		if r.dashboards.Spec.OpensearchConfig.PasswordFrom != nil {
			env = append(env, corev1.EnvVar{
				Name: "OPENSEARCH_PASSWORD",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: r.dashboards.Spec.OpensearchConfig.PasswordFrom,
				},
			})
		}
	}
	return
}

func (r *Reconciler) dashboardVolumes() (volumes []corev1.Volume) {
	volumes = append(volumes, corev1.Volume{
		Name: "certs",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: func() string {
					if r.dashboards.Spec.TLSSecret != nil {
						return r.dashboards.Spec.TLSSecret.Name
					}
					return fmt.Sprintf("%s-osdb-tls", r.dashboards.Name)
				}(),
			},
		},
	})
	volumes = append(volumes, corev1.Volume{
		Name: "config",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: fmt.Sprintf("%s-osdb-config", r.dashboards.Name),
			},
		},
	})
	if r.dashboards.Spec.OpensearchCluster != nil {
		volumes = append(volumes, corev1.Volume{
			Name: "ca",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: fmt.Sprintf("%s-os-certs", r.dashboards.Spec.OpensearchCluster.Name),
					Items: []corev1.KeyToPath{
						{
							Key:  pki.RESTCASecretField,
							Path: pki.RESTCASecretField,
						},
					},
				},
			},
		})
	}
	return
}

func (r *Reconciler) dashboardVolumeMounts() (volumeMounts []corev1.VolumeMount) {
	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      "certs",
		ReadOnly:  true,
		MountPath: "/usr/share/opensearch-dashboards/tls",
	})
	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      "config",
		SubPath:   "opensearch_dashboards.yml",
		MountPath: "/usr/share/opensearch-dashboards/config/opensearch_dashboards.yml",
		ReadOnly:  true,
	})

	if r.dashboards.Spec.OpensearchCluster != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "ca",
			SubPath:   pki.RESTCASecretField,
			MountPath: fmt.Sprintf("/usr/share/opensearch-dashboards/%s", pki.RESTCASecretField),
			ReadOnly:  true,
		})
	}
	return
}
