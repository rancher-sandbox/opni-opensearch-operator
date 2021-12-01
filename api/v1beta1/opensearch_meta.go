package v1beta1

import (
	"fmt"
	"path"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/pointer"
)

type OpensearchRole string

const (
	OpensearchDataRole       OpensearchRole = "data"
	OpensearchClientRole     OpensearchRole = "client"
	OpensearchMasterRole     OpensearchRole = "master"
	OpensearchDashboardsRole OpensearchRole = "dashboards"
)

func (s ImageSpec) GetImagePullPolicy() (_ corev1.PullPolicy) {
	if p := s.ImagePullPolicy; p != nil {
		return *p
	}
	return
}

func (s ImageSpec) GetImage() string {
	if s.Image == nil {
		return ""
	}
	return *s.Image
}

type ImageResolver struct {
	Version             string
	ImageName           string
	DefaultRepo         string
	DefaultRepoOverride *string
	ImageOverride       *ImageSpec
}

func (r ImageResolver) Resolve() (result ImageSpec) {
	// If a custom image is specified, use it.
	if r.ImageOverride != nil {
		if r.ImageOverride.ImagePullPolicy != nil {
			result.ImagePullPolicy = r.ImageOverride.ImagePullPolicy
		}
		if len(r.ImageOverride.ImagePullSecrets) > 0 {
			result.ImagePullSecrets = r.ImageOverride.ImagePullSecrets
		}
		if r.ImageOverride.Image != nil {
			// If image is set, nothing else needs to be done
			result.Image = r.ImageOverride.Image
			return
		}
	}

	// If a different image repo is requested, use that with the default image
	// name and version tag.
	defaultRepo := r.DefaultRepo
	if r.DefaultRepoOverride != nil {
		defaultRepo = *r.DefaultRepoOverride
	}
	version := r.Version
	if r.Version == "" {
		version = "latest"
	}
	result.Image = pointer.String(fmt.Sprintf("%s:%s",
		path.Join(defaultRepo, r.ImageName), version))
	return
}

func (e OpensearchRole) GetNodeSelector(opensearchCluster *OpensearchCluster) map[string]string {
	switch e {
	case OpensearchDataRole:
		return opensearchCluster.Spec.Data.NodeSelector
	case OpensearchMasterRole:
		return opensearchCluster.Spec.Master.NodeSelector
	case OpensearchClientRole:
		return opensearchCluster.Spec.Client.NodeSelector
	default:
		return map[string]string{}
	}
}

func (e OpensearchRole) GetTolerations(opensearchCluster *OpensearchCluster) []corev1.Toleration {
	switch e {
	case OpensearchDataRole:
		return opensearchCluster.Spec.Data.Tolerations
	case OpensearchMasterRole:
		return opensearchCluster.Spec.Master.Tolerations
	case OpensearchClientRole:
		return opensearchCluster.Spec.Client.Tolerations
	default:
		return []corev1.Toleration{}
	}
}

func (c *OpensearchCluster) GetState() string {
	return string(c.Status.State)
}

func (c *OpensearchCluster) GetConditions() []string {
	return c.Status.Conditions
}
