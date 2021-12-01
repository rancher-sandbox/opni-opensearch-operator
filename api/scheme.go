package api

import (
	"github.com/rancher/opni-opensearch-operator/api/v1beta1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

// InitScheme adds all the types needed by opni-opensearch-operator to the provided scheme.
func InitScheme(scheme *runtime.Scheme) {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(apiextv1.AddToScheme(scheme))
	utilruntime.Must(v1beta1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}
