package opensearch

import (
	"fmt"
	"math"

	"github.com/rancher/opni-opensearch-operator/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

var (
	opensearchContainerEnv = []corev1.EnvVar{
		{
			Name:  "cluster.name",
			Value: "opensearch",
		},
		{
			Name:  "network.host",
			Value: "0.0.0.0",
		},
	}
	downwardsAPIEnv = []corev1.EnvVar{
		{
			Name: "node.name",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.name",
				},
			},
		},
		{
			Name: "KUBERNETES_NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.namespace",
				},
			},
		},
		{
			Name: "PROCESSORS",
			ValueFrom: &corev1.EnvVarSource{
				ResourceFieldRef: &corev1.ResourceFieldSelector{
					Resource: "limits.cpu",
				},
			},
		},
	}
)

func (r *Reconciler) opensearchNodeTypeEnv(role v1beta1.OpensearchRole) []corev1.EnvVar {
	envVars := []corev1.EnvVar{
		{
			Name:  "node.master",
			Value: fmt.Sprint(role == v1beta1.OpensearchMasterRole),
		},
		{
			Name:  "node.ingest",
			Value: fmt.Sprint(role == v1beta1.OpensearchDataRole),
		},
		{
			Name:  "node.data",
			Value: fmt.Sprint(role == v1beta1.OpensearchDataRole),
		},
		{
			Name:  "discovery.seed_hosts",
			Value: fmt.Sprintf("%s-os-discovery.%s", r.opensearchCluster.Name, r.opensearchCluster.Namespace),
		},
	}
	if role == v1beta1.OpensearchMasterRole && (r.masterSingleton() || !r.opensearchCluster.Status.Initialized) {
		envVars = append(envVars, corev1.EnvVar{
			Name:  "cluster.initial_master_nodes",
			Value: fmt.Sprintf("%s-%s-0", r.opensearchCluster.Name, OpensearchMasterSuffix),
		})
	}
	envVars = append(envVars, role.GetExtraEnvVars(r.opensearchCluster)...)
	return envVars
}

func (r *Reconciler) javaOptsEnv(role v1beta1.OpensearchRole) []corev1.EnvVar {
	return []corev1.EnvVar{
		{
			Name: "OPENSEARCH_JAVA_OPTS",
			Value: javaOpts(func() *corev1.ResourceRequirements {
				switch role {
				case v1beta1.OpensearchDataRole:
					if res := r.opensearchCluster.Spec.Data.Resources; res != nil {
						return res
					}
				case v1beta1.OpensearchClientRole:
					if res := r.opensearchCluster.Spec.Client.Resources; res != nil {
						return res
					}
				case v1beta1.OpensearchMasterRole:
					if res := r.opensearchCluster.Spec.Master.Resources; res != nil {
						return res
					}
				}
				return &corev1.ResourceRequirements{}
			}()),
		},
	}
}

func (r *Reconciler) zenMastersEnv() []corev1.EnvVar {
	if r.opensearchCluster.Spec.Master.Replicas == nil {
		return []corev1.EnvVar{}
	}
	quorum := math.Round(float64(*r.opensearchCluster.Spec.Master.Replicas) / 2)
	return []corev1.EnvVar{
		{
			Name:  "discovery.zen.minimum_master_nodes",
			Value: fmt.Sprintf("%.0f", quorum),
		},
	}
}

func (r *Reconciler) esPasswordEnv() []corev1.EnvVar {
	return []corev1.EnvVar{
		{
			Name: "ES_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: r.opensearchCluster.Status.Auth.OpensearchAuthSecretKeyRef,
			},
		},
	}
}

func javaOpts(req *corev1.ResourceRequirements) string {
	if memLimit, ok := req.Limits[corev1.ResourceMemory]; ok {
		return fmt.Sprintf("-Dlog4j2.formatMsgNoLookups=true -Xms%[1]dm -Xmx%[1]dm", memLimit.ScaledValue(resource.Mega)/2)
	}
	return "-Dlog4j2.formatMsgNoLookups=true -Xms512m -Xmx512m"
}

func combineEnvVars(envVars ...[]corev1.EnvVar) (result []corev1.EnvVar) {
	for _, envVars := range envVars {
		result = append(result, envVars...)
	}
	return
}
