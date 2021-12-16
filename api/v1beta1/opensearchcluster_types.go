/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1beta1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ImageSpec struct {
	Image            *string                       `json:"image,omitempty"`
	ImagePullPolicy  *corev1.PullPolicy            `json:"imagePullPolicy,omitempty"`
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
}

// OpensearchClusterSpec defines the desired state of OpensearchCluster
type OpensearchClusterSpec struct {
	Version     string     `json:"version"`
	DefaultRepo *string    `json:"defaultRepo,omitempty"`
	Image       *ImageSpec `json:"image,omitempty"`
	// Secret containing an item "logging.yml" with the contents of the
	// elasticsearch logging config.
	ConfigSecret *corev1.LocalObjectReference `json:"configSecret,omitempty"`
	// Reference to a secret containing the auth config.  Must be a key called config.yml
	AuthConfigSecret *corev1.LocalObjectReference `json:"authConfigSecret,omitempty"`
	// Reference to a secret key containing the desired admin password
	AdminPasswordFrom  *corev1.SecretKeySelector `json:"adminPasswordFrom,omitempty"`
	Master             OpensearchWorkloadOptions `json:"master,omitempty"`
	Data               OpensearchWorkloadOptions `json:"data,omitempty"`
	Client             OpensearchWorkloadOptions `json:"client,omitempty"`
	GlobalNodeSelector map[string]string         `json:"globalNodeSelector,omitempty"`
	GlobalTolerations  []corev1.Toleration       `json:"globalTolerations,omitempty"`
}

type OpensearchWorkloadOptions struct {
	Replicas     *int32                       `json:"replicas,omitempty"`
	Resources    *corev1.ResourceRequirements `json:"resources,omitempty"`
	Affinity     *corev1.Affinity             `json:"affinity,omitempty"`
	NodeSelector map[string]string            `json:"nodeSelector,omitempty"`
	Tolerations  []corev1.Toleration          `json:"tolerations,omitempty"`
	Persistence  *PersistenceSpec             `json:"persistence,omitempty"`
	ExtraEnvVars []corev1.EnvVar              `json:"extraEnvVars,omitempty"`
}

type PersistenceSpec struct {
	Enabled          bool                                `json:"enabled,omitempty"`
	StorageClassName *string                             `json:"storageClass,omitempty"`
	AccessModes      []corev1.PersistentVolumeAccessMode `json:"accessModes,omitempty"`
	// Storage size request. Defaults to 10Gi.
	Request resource.Quantity `json:"request,omitempty"`
}

type ClusterState string

const (
	OpensearchClusterStateError   ClusterState = "Error"
	OpensearchClusterStateWorking ClusterState = "Working"
	OpensearchClusterStateReady   ClusterState = "Ready"
)

type AuthStatus struct {
	GenerateOpensearchHash     *bool                     `json:"generateOpensearchHash,omitempty"`
	OpensearchAuthSecretKeyRef *corev1.SecretKeySelector `json:"elasticsearchAuthSecretKeyRef,omitempty"`
}

// OpensearchClusterStatus defines the observed state of OpensearchCluster
type OpensearchClusterStatus struct {
	Conditions  []string     `json:"conditions,omitempty"`
	State       ClusterState `json:"opensearchState,omitempty"`
	Version     *string      `json:"version,omitempty"`
	Initialized bool         `json:"initialized,omitempty"`
	Auth        AuthStatus   `json:"auth,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// OpensearchCluster is the Schema for the opensearchclusters API
type OpensearchCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpensearchClusterSpec   `json:"spec,omitempty"`
	Status OpensearchClusterStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// OpensearchClusterList contains a list of OpensearchCluster
type OpensearchClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpensearchCluster `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpensearchCluster{}, &OpensearchClusterList{})
}
