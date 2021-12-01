package resources

import (
	"github.com/rancher/opni-opensearch-operator/api/v1beta1"
)

const (
	OpensearchClusterName = "opensearch.opni.io/cluster-name"
	AppNameLabel          = "app.kubernetes.io/name"
	PartOfLabel           = "app.kubernetes.io/part-of"
	HostTopologyKey       = "kubernetes.io/hostname"
)

func CombineLabels(maps ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

type OpensearchLabels map[string]string

func NewOpensearchLabels() OpensearchLabels {
	return map[string]string{
		"app": "opensearch",
	}
}

func (l OpensearchLabels) WithRole(role v1beta1.OpensearchRole) OpensearchLabels {
	copied := map[string]string{}
	for k, v := range l {
		copied[k] = v
	}
	copied["role"] = string(role)
	return copied
}

func (l OpensearchLabels) Role() v1beta1.OpensearchRole {
	role, ok := l["role"]
	if !ok {
		return ""
	}
	return v1beta1.OpensearchRole(role)
}
