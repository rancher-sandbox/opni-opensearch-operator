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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/banzaicloud/operator-tools/pkg/reconciler"
	"github.com/rancher/opni-opensearch-operator/api/v1beta1"
	"github.com/rancher/opni-opensearch-operator/pkg/resources"
	"github.com/rancher/opni-opensearch-operator/pkg/resources/dashboards"
	"github.com/rancher/opni/pkg/util"
)

// DashboardsReconciler reconciles a OpensearchDashboard object
type DashboardsReconciler struct {
	client.Client
	scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=opensearch.opni.io,resources=dashboards,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=opensearch.opni.io,resources=dashboards/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=opensearch.opni.io,resources=dashboards/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services;pods,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the OpensearchDashboard object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.10.0/pkg/reconcile
func (r *DashboardsReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	dashboardsObject := &v1beta1.Dashboards{}
	err := r.Get(ctx, req.NamespacedName, dashboardsObject)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	dashboardsReconciler := dashboards.NewReconciler(ctx, r, dashboardsObject,
		reconciler.WithEnableRecreateWorkload(),
		reconciler.WithScheme(r.scheme),
	)

	reconcilers := []resources.ComponentReconciler{
		dashboardsReconciler.Reconcile,
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
func (r *DashboardsReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Client = mgr.GetClient()
	r.scheme = mgr.GetScheme()
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1beta1.Dashboards{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Complete(r)
}
