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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DashboardsSpec defines the desired state of OpensearchDashboard
type DashboardsSpec struct {
	OpensearchCluster *OpensearchClusterRef        `json:"opensearch,omitempty"`
	OpensearchURL     string                       `json:"opensearchUrl,omitempty"`
	Version           string                       `json:"version"`
	DefaultRepo       *string                      `json:"defaultRepo,omitempty"`
	Image             *ImageSpec                   `json:"image,omitempty"`
	Replicas          *int32                       `json:"replicas,omitempty"`
	Resources         *corev1.ResourceRequirements `json:"resources,omitempty"`
	Affinity          *corev1.Affinity             `json:"affinity,omitempty"`
	NodeSelector      map[string]string            `json:"nodeSelector,omitempty"`
	Tolerations       []corev1.Toleration          `json:"tolerations,omitempty"`
	Persistence       *PersistenceSpec             `json:"persistence,omitempty"`
}

type OpensearchClusterRef struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namepace,omitempty"`
}

// DashboardsStatus defines the observed state of OpensearchDashboard
type DashboardsStatus struct {
	Conditions []string     `json:"conditions,omitempty"`
	State      ClusterState `json:"opensearchState,omitempty"`
	Version    *string      `json:"version,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Dashboards is the Schema for the ashboards API
type Dashboards struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DashboardsSpec   `json:"spec,omitempty"`
	Status DashboardsStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// DashboardList contains a list of OpensearchDashboard
type DashboardsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Dashboards `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Dashboards{}, &DashboardsList{})
}
