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

package controllers

import (
	"context"

	"github.com/banzaicloud/operator-tools/pkg/reconciler"
	"github.com/rancher/opni/pkg/util"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/rancher/opni-opensearch-operator/api/v1beta1"
	"github.com/rancher/opni-opensearch-operator/pkg/resources"
	"github.com/rancher/opni-opensearch-operator/pkg/resources/opensearch"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// OpensearchClusterReconciler reconciles a OpensearchCluster object
type OpensearchClusterReconciler struct {
	client.Client
	scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=opensearch.opni.io,resources=opensearchclusters,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=opensearch.opni.io,resources=opensearchclusters/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=opensearch.opni.io,resources=opensearchclusters/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=statefulsets;deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=configmaps;services;secrets;pods,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the OpensearchCluster object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.10.0/pkg/reconcile
func (r *OpensearchClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	opensearchCluster := &v1beta1.OpensearchCluster{}
	err := r.Get(ctx, req.NamespacedName, opensearchCluster)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	opensearchReconciler := opensearch.NewReconciler(ctx, r, opensearchCluster,
		reconciler.WithEnableRecreateWorkload(),
		reconciler.WithScheme(r.scheme),
	)

	reconcilers := []resources.ComponentReconciler{
		opensearchReconciler.Reconcile,
		opensearchReconciler.ReconcileOpensearchUpgrade,
	}

	for _, rec := range reconcilers {
		op := util.LoadResult(rec())
		if op.ShouldRequeue() {
			return op.Result()
		}
	}

	return util.DoNotRequeue().Result()
}

// SetupWithManager sets up the controller with the Manager.
func (r *OpensearchClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Client = mgr.GetClient()
	r.scheme = mgr.GetScheme()
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1beta1.OpensearchCluster{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
