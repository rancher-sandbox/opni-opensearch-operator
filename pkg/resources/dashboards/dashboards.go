package dashboards

import (
	"context"
	"fmt"

	"emperror.dev/errors"
	"github.com/banzaicloud/operator-tools/pkg/reconciler"
	"github.com/rancher/opni-opensearch-operator/api/v1beta1"
	"github.com/rancher/opni-opensearch-operator/pkg/resources"
	"github.com/rancher/opni-opensearch-operator/pkg/resources/dashboards/certs"
	"github.com/rancher/opni/pkg/util"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type Reconciler struct {
	reconciler.ResourceReconciler
	dashboards *v1beta1.Dashboards
	client     client.Client
	ctx        context.Context
}

func NewReconciler(
	ctx context.Context,
	client client.Client,
	dashboards *v1beta1.Dashboards,
	opts ...reconciler.ResourceReconcilerOption,
) *Reconciler {
	return &Reconciler{
		ResourceReconciler: reconciler.NewReconcilerWith(client,
			append(opts, reconciler.WithLog(log.FromContext(ctx)))...),
		client:     client,
		dashboards: dashboards,
		ctx:        ctx,
	}
}

func (r *Reconciler) Reconcile() (retResult *reconcile.Result, retErr error) {
	lg := log.FromContext(r.ctx)
	conditions := []string{}

	defer func() {
		// When the reconciler is done, figure out what the state of the opensearchCluster
		// is and set it in the state field accordingly.
		op := util.LoadResult(retResult, retErr)
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := r.client.Get(r.ctx, client.ObjectKeyFromObject(r.dashboards), r.dashboards); err != nil {
				return err
			}
			r.dashboards.Status.Conditions = conditions
			if op.ShouldRequeue() {
				if retErr != nil {
					// If an error occurred, the state should be set to error
					r.dashboards.Status.State = v1beta1.OpensearchClusterStateError
				} else {
					// If no error occurred, but we need to requeue, the state should be
					// set to working
					r.dashboards.Status.State = v1beta1.OpensearchClusterStateWorking
				}
			} else if len(r.dashboards.Status.Conditions) == 0 {
				// If we are not requeueing and there are no conditions, the state should
				// be set to ready
				r.dashboards.Status.State = v1beta1.OpensearchClusterStateReady
				// Set the opensearch version once it's been created
				if r.dashboards.Status.Version == nil {
					r.dashboards.Status.Version = &r.dashboards.Spec.Version
				}
			}
			return r.client.Status().Update(r.ctx, r.dashboards)
		})

		if err != nil {
			lg.Error(err, "failed to update status")
		}
	}()

	if r.dashboards.Spec.OpensearchCluster == nil && r.dashboards.Spec.TLSSecret == nil {
		retErr = errors.New("tlsSecret or opensearchCluster required to set TLS for dashboards")
		return
	}

	allResources := []resources.Resource{}
	certsReconciler := certs.NewCertsReconciler(r.ctx, r.client, r.dashboards)
	certResource := certsReconciler.CertSecret()

	dashboardsResources, err := r.DashboardsResources()
	if err != nil {
		retErr = errors.Combine(retErr, err)
		conditions = append(conditions, err.Error())
		lg.Error(err, "Error when reconciling opensearch.")
		return
	}

	allResources = append(allResources, certResource)
	allResources = append(allResources, dashboardsResources...)

	for _, factory := range allResources {
		o, state, err := factory()
		if err != nil {
			retErr = errors.WrapIf(err, "failed to create object")
			return
		}
		if o == nil {
			panic(fmt.Sprintf("reconciler %#v created a nil object", factory))
		}
		result, err := r.ReconcileResource(o, state)
		if err != nil {
			retErr = errors.WrapWithDetails(err, "failed to reconcile resource",
				"resource", o.GetObjectKind().GroupVersionKind())
			return
		}
		if result != nil {
			retResult = result
		}
	}

	return
}

func (r *Reconciler) DashboardsResources() (resourceList []resources.Resource, _ error) {
	resourceList = append(resourceList, r.dashboardsConfigSecret())
	resourceList = append(resourceList, r.dashboardsServices()...)
	resourceList = append(resourceList, r.dashboardshWorkloads()...)
	return
}
