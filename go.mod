module github.com/rancher/opni-opensearch-operator

go 1.16

require (
	emperror.dev/errors v0.8.0
	github.com/banzaicloud/operator-tools v0.26.3
	github.com/go-logr/logr v0.4.0
	github.com/kralicky/kmatch v0.0.0-20210910033132-e5a80a7a45e6
	github.com/onsi/ginkgo v1.16.5-0.20210926212817-d0c597ffc7d0
	github.com/onsi/gomega v1.16.0
	github.com/opensearch-project/opensearch-go v1.0.0
	github.com/phayes/freeport v0.0.0-20180830031419-95f893ade6f2
	github.com/rancher/opni v0.2.1
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	k8s.io/api v0.22.3
	k8s.io/apiextensions-apiserver v0.22.2
	k8s.io/apimachinery v0.22.3
	k8s.io/client-go v0.22.2
	k8s.io/utils v0.0.0-20210820185131-d34e5cb4466e
	sigs.k8s.io/controller-runtime v0.10.1
)

replace (
	github.com/NVIDIA/gpu-operator => github.com/kralicky/gpu-operator v1.8.1-0.20211112183255-72529edf38be
	github.com/banzaicloud/logging-operator => github.com/dbason/logging-operator v0.0.0-20211104200206-ca165c7327da
	github.com/banzaicloud/logging-operator/pkg/sdk => github.com/dbason/logging-operator/pkg/sdk v0.0.0-20211104200206-ca165c7327da
	// github.com/banzaicloud/logging-operator/pkg/sdk => github.com/banzaicloud/logging-operator/pkg/sdk v0.7.7
	github.com/openshift/api => github.com/openshift/api v0.0.0-20210216211028-bb81baaf35cd
	// Because of a dependency chain to Coretx
	k8s.io/client-go => k8s.io/client-go v0.22.3
)
