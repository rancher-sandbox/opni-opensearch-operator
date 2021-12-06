package opensearch

import (
	"fmt"

	"github.com/rancher/opni-opensearch-operator/api/v1beta1"
	"github.com/rancher/opni-opensearch-operator/pkg/resources"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	securityConfigPath  = "/usr/share/opensearch/plugins/opensearch-security/securityconfig/"
	authConfigSecretKey = "config.yml"
)

func (r *Reconciler) opensearchWorkloads() []resources.Resource {
	return []resources.Resource{
		r.opensearchMasterWorkload(),
		r.opensearchDataWorkload(),
		r.opensearchClientWorkload(),
	}
}

func (r *Reconciler) opensearchDataWorkload() resources.Resource {
	labels := resources.NewOpensearchLabels().
		WithRole(v1beta1.OpensearchDataRole)

	workload := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", r.opensearchCluster.Name, OpensearchDataSuffix),
			Namespace: r.opensearchCluster.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: r.opensearchCluster.Spec.Data.Replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			UpdateStrategy: appsv1.StatefulSetUpdateStrategy{
				Type: appsv1.OnDeleteStatefulSetStrategyType,
			},
			Template: r.opensearchPodTemplate(labels),
		},
	}

	workload.Spec.Template.Spec.Affinity =
		r.opensearchCluster.Spec.Data.Affinity
	if r.opensearchCluster.Spec.Data.Resources != nil {
		workload.Spec.Template.Spec.Containers[0].Resources =
			*r.opensearchCluster.Spec.Data.Resources
	}

	ctrl.SetControllerReference(r.opensearchCluster, workload, r.client.Scheme())
	r.configurePVC(workload, r.opensearchCluster.Spec.Data.Persistence)
	return resources.Present(workload)
}

func (r *Reconciler) opensearchPodTemplate(
	labels resources.OpensearchLabels,
) corev1.PodTemplateSpec {
	imageSpec := r.opensearchImageSpec()
	podTemplate := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: labels,
		},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{
				initSysctlContainer(),
			},
			Containers: []corev1.Container{
				{
					Name:            "opensearch",
					Image:           imageSpec.GetImage(),
					ImagePullPolicy: imageSpec.GetImagePullPolicy(),
					Ports:           containerPortsForRole(labels.Role()),
					VolumeMounts: []corev1.VolumeMount{
						configVolumeMount(),
						internalusersVolumeMount(),
					},
					LivenessProbe: &corev1.Probe{
						InitialDelaySeconds: 60,
						PeriodSeconds:       10,
						Handler: corev1.Handler{
							TCPSocket: &corev1.TCPSocketAction{
								Port: intstr.FromString("transport"),
							},
						},
					},
					ReadinessProbe: &corev1.Probe{
						InitialDelaySeconds: 60,
						PeriodSeconds:       30,
						Handler: corev1.Handler{
							Exec: &corev1.ExecAction{
								Command: []string{
									"/bin/bash",
									"-c",
									"curl -k -u admin:${ES_PASSWORD} --silent --fail https://localhost:9200",
								},
							},
						},
					},
					SecurityContext: &corev1.SecurityContext{
						Capabilities: &corev1.Capabilities{
							Add: []corev1.Capability{"SYS_CHROOT"},
						},
					},
					Env: combineEnvVars(
						opensearchContainerEnv,
						downwardsAPIEnv,
						r.opensearchNodeTypeEnv(labels.Role()),
						r.zenMastersEnv(),
						r.esPasswordEnv(),
						r.javaOptsEnv(labels.Role()),
					),
				},
			},
			NodeSelector: r.opensearchNodeSelector(labels.Role()),
			Tolerations:  r.opensearchTolerations(labels.Role()),
			Volumes: []corev1.Volume{
				configVolume(),
				internalusersVolume(r.opensearchCluster.Name),
			},
			ImagePullSecrets: imageSpec.ImagePullSecrets,
		},
	}

	if r.opensearchCluster.Spec.AuthConfigSecret != nil {
		podTemplate.Spec.Volumes = append(podTemplate.Spec.Volumes, r.authConfigVolume())
		podTemplate.Spec.Containers[0].VolumeMounts = append(podTemplate.Spec.Containers[0].VolumeMounts, r.authConfigVolumeMount())
	}

	return podTemplate
}

func containerPortsForRole(role v1beta1.OpensearchRole) []corev1.ContainerPort {
	switch role {
	case v1beta1.OpensearchDataRole:
		return []corev1.ContainerPort{
			containerPort(transportPort),
		}
	case v1beta1.OpensearchClientRole, v1beta1.OpensearchMasterRole:
		return []corev1.ContainerPort{
			containerPort(httpPort),
			containerPort(transportPort),
			containerPort(metricsPort),
			containerPort(rcaPort),
		}
	default:
		return nil
	}
}

func (r *Reconciler) opensearchMasterWorkload() resources.Resource {
	labels := resources.NewOpensearchLabels().
		WithRole(v1beta1.OpensearchMasterRole)

	workload := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", r.opensearchCluster.Name, OpensearchMasterSuffix),
			Namespace: r.opensearchCluster.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: r.opensearchCluster.Spec.Master.Replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			UpdateStrategy: appsv1.StatefulSetUpdateStrategy{
				RollingUpdate: &appsv1.RollingUpdateStatefulSetStrategy{
					Partition: func() *int32 {
						if r.opensearchCluster.Status.Version == nil {
							return pointer.Int32(0)
						}
						if *r.opensearchCluster.Status.Version == r.opensearchCluster.Spec.Version {
							return pointer.Int32(0)
						}
						return r.opensearchCluster.Spec.Master.Replicas
					}(),
				},
			},
			Template: r.opensearchPodTemplate(labels),
		},
	}

	workload.Spec.Template.Spec.Affinity =
		r.opensearchCluster.Spec.Master.Affinity
	if r.opensearchCluster.Spec.Master.Resources != nil {
		workload.Spec.Template.Spec.Containers[0].Resources =
			*r.opensearchCluster.Spec.Master.Resources
	}

	ctrl.SetControllerReference(r.opensearchCluster, workload, r.client.Scheme())
	r.configurePVC(workload, r.opensearchCluster.Spec.Master.Persistence)
	return resources.Present(workload)
}

func (r *Reconciler) configurePVC(workload *appsv1.StatefulSet, persistence *v1beta1.PersistenceSpec) {
	// Insert the data volume into the pod template.
	workload.Spec.Template.Spec.InitContainers = append(
		workload.Spec.Template.Spec.InitContainers, fixMountContainer())
	workload.Spec.Template.Spec.Containers[0].VolumeMounts = append(
		workload.Spec.Template.Spec.Containers[0].VolumeMounts, dataVolumeMount())

	// Set up defaults
	pvc := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: "opensearch-data",
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("10Gi"),
				},
			},
		},
	}

	usePersistence := false
	if persistence != nil {
		if !persistence.Enabled {
			// Persistence disabled
			return
		}
		usePersistence = true
		if len(persistence.AccessModes) > 0 {
			pvc.Spec.AccessModes = persistence.AccessModes
		}
		pvc.Spec.StorageClassName = persistence.StorageClassName
		resourceRequest := persistence.Request
		if resourceRequest.IsZero() {
			resourceRequest = resource.MustParse("10Gi")
		}
		pvc.Spec.Resources.Requests = corev1.ResourceList{
			corev1.ResourceStorage: resourceRequest,
		}
	}

	// If we are using persistent storage, create a PVC. Otherwise, create an
	// emptyDir volume.
	if usePersistence {
		workload.Spec.VolumeClaimTemplates =
			append(workload.Spec.VolumeClaimTemplates, pvc)
		workload.Spec.Template.Spec.Volumes =
			append(workload.Spec.Template.Spec.Volumes,
				corev1.Volume{
					Name: "opensearch-data",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
							ClaimName: "opensearch-data",
						},
					},
				},
			)
	} else {
		workload.Spec.Template.Spec.Volumes =
			append(workload.Spec.Template.Spec.Volumes,
				corev1.Volume{
					Name: "opensearch-data",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
			)
	}
}

func (r *Reconciler) opensearchClientWorkload() resources.Resource {
	labels := resources.NewOpensearchLabels().
		WithRole(v1beta1.OpensearchClientRole)

	workload := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", r.opensearchCluster.Name, OpensearchClientSuffix),
			Namespace: r.opensearchCluster.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: r.opensearchCluster.Spec.Client.Replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: r.opensearchPodTemplate(labels),
		},
	}

	workload.Spec.Template.Spec.Affinity =
		r.opensearchCluster.Spec.Client.Affinity
	if r.opensearchCluster.Spec.Client.Resources != nil {
		workload.Spec.Template.Spec.Containers[0].Resources =
			*r.opensearchCluster.Spec.Client.Resources
	}

	ctrl.SetControllerReference(r.opensearchCluster, workload, r.client.Scheme())
	return resources.Present(workload)
}

func initSysctlContainer() corev1.Container {
	return corev1.Container{
		Name:  "init-sysctl",
		Image: "busybox:1.27.2",
		Command: []string{
			"sysctl",
			"-w",
			"vm.max_map_count=262144",
		},
		SecurityContext: &corev1.SecurityContext{
			Privileged: pointer.Bool(true),
		},
	}
}

func fixMountContainer() corev1.Container {
	return corev1.Container{
		Name:  "fix-mount",
		Image: "busybox:1.27.2",
		Command: []string{
			"sh",
			"-c",
			"chown -R 1000:1000 /usr/share/opensearch/data",
		},
		VolumeMounts: []corev1.VolumeMount{
			dataVolumeMount(),
		},
	}
}

func dataVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      "opensearch-data",
		MountPath: "/usr/share/opensearch/data",
	}
}

func configVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      "config",
		MountPath: "/usr/share/opensearch/config/logging.yml",
		SubPath:   "logging.yml",
	}
}

func configVolume() corev1.Volume {
	return corev1.Volume{
		Name: "config",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: "opni-es-config",
			},
		},
	}
}

func internalusersVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      "internalusers",
		MountPath: fmt.Sprintf("%s%s", securityConfigPath, internalUsersKey),
		SubPath:   internalUsersKey,
	}
}

func internalusersVolume(clusterName string) corev1.Volume {
	internalUsersSecretName := fmt.Sprintf("%s%s", clusterName, internalUsersSecretSuffix)
	return corev1.Volume{
		Name: "internalusers",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: internalUsersSecretName,
			},
		},
	}
}

func (r *Reconciler) authConfigVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      "authconfig",
		MountPath: fmt.Sprintf("%s%s", securityConfigPath, authConfigSecretKey),
		SubPath:   authConfigSecretKey,
	}
}

func (r *Reconciler) authConfigVolume() corev1.Volume {
	return corev1.Volume{
		Name: "authconfig",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: r.opensearchCluster.Spec.AuthConfigSecret.Name,
			},
		},
	}
}

func (r *Reconciler) opensearchImageSpec() v1beta1.ImageSpec {
	return v1beta1.ImageResolver{
		Version:             r.opensearchCluster.Spec.Version,
		ImageName:           "opensearch",
		DefaultRepo:         "docker.io/opensearchproject",
		DefaultRepoOverride: r.opensearchCluster.Spec.DefaultRepo,
		ImageOverride:       r.opensearchCluster.Spec.Image,
	}.Resolve()
}

func (r *Reconciler) opensearchNodeSelector(role v1beta1.OpensearchRole) map[string]string {
	if s := role.GetNodeSelector(r.opensearchCluster); len(s) > 0 {
		return s
	}
	return r.opensearchCluster.Spec.GlobalNodeSelector
}

func (r *Reconciler) opensearchTolerations(role v1beta1.OpensearchRole) []corev1.Toleration {
	return append(r.opensearchCluster.Spec.GlobalTolerations, role.GetTolerations(r.opensearchCluster)...)
}
