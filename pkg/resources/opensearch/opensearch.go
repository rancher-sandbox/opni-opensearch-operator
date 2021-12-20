package opensearch

import (
	"context"
	"fmt"
	"time"

	"emperror.dev/errors"
	"github.com/banzaicloud/operator-tools/pkg/reconciler"
	"github.com/opensearch-project/opensearch-go"
	"github.com/rancher/opni-opensearch-operator/api/v1beta1"
	"github.com/rancher/opni-opensearch-operator/pkg/resources"
	"github.com/rancher/opni-opensearch-operator/pkg/resources/opensearch/certs"
	"github.com/rancher/opni/pkg/util"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var (
	ErrOpensearchUpgradeFailed = errors.New("opensearch upgrade failed")
)

type Reconciler struct {
	reconciler.ResourceReconciler
	opensearchCluster *v1beta1.OpensearchCluster
	client            client.Client
	ctx               context.Context
	osClient          *opensearch.Client
}

func NewReconciler(
	ctx context.Context,
	client client.Client,
	opensearchCluster *v1beta1.OpensearchCluster,
	opts ...reconciler.ResourceReconcilerOption,
) *Reconciler {
	return &Reconciler{
		ResourceReconciler: reconciler.NewReconcilerWith(client,
			append(opts, reconciler.WithLog(log.FromContext(ctx)))...),
		client:            client,
		opensearchCluster: opensearchCluster,
		ctx:               ctx,
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
			if err := r.client.Get(r.ctx, client.ObjectKeyFromObject(r.opensearchCluster), r.opensearchCluster); err != nil {
				return err
			}
			r.opensearchCluster.Status.Conditions = conditions
			if op.ShouldRequeue() {
				if retErr != nil {
					// If an error occurred, the state should be set to error
					r.opensearchCluster.Status.State = v1beta1.OpensearchClusterStateError
				} else {
					// If no error occurred, but we need to requeue, the state should be
					// set to working
					r.opensearchCluster.Status.State = v1beta1.OpensearchClusterStateWorking
				}
			} else if len(r.opensearchCluster.Status.Conditions) == 0 {
				// If we are not requeueing and there are no conditions, the state should
				// be set to ready
				r.opensearchCluster.Status.State = v1beta1.OpensearchClusterStateReady
				// Set the opensearch version once it's been created
				if r.opensearchCluster.Status.Version == nil {
					r.opensearchCluster.Status.Version = &r.opensearchCluster.Spec.Version
				}
			}
			return r.client.Status().Update(r.ctx, r.opensearchCluster)
		})

		if err != nil {
			lg.Error(err, "failed to update status")
		}
	}()

	allResources := []resources.Resource{}

	osResources, err := r.OpensearchResources()
	if err != nil {
		retErr = errors.Combine(retErr, err)
		conditions = append(conditions, err.Error())
		lg.Error(err, "Error when reconciling opensearch.")
		return
	}

	recreateCerts := !(r.masterSingleton() || r.dataSingleton())
	certsReconciler := certs.NewReconciler(r.ctx, r.client, recreateCerts, r.opensearchCluster)
	certResources, err := certsReconciler.CertSecrets()
	if err != nil {
		retErr = errors.Combine(retErr, err)
		conditions = append(conditions, err.Error())
		lg.Error(err, "Error when reconciling opensearch certs.")
		return
	}

	allResources = append(allResources, osResources...)
	allResources = append(allResources, certResources...)

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

	// If the statefulsets aren't ready just requeue so we can reconcile the certs
	osData := &appsv1.StatefulSet{}
	err = r.client.Get(r.ctx, types.NamespacedName{
		Name:      fmt.Sprintf("%s-%s", r.opensearchCluster.Name, resources.OpensearchDataSuffix),
		Namespace: r.opensearchCluster.Namespace,
	}, osData)
	if err != nil {
		return nil, err
	}

	osMaster := &appsv1.StatefulSet{}
	err = r.client.Get(r.ctx, types.NamespacedName{
		Name:      fmt.Sprintf("%s-%s", r.opensearchCluster.Name, resources.OpensearchMasterSuffix),
		Namespace: r.opensearchCluster.Namespace,
	}, osMaster)
	if err != nil {
		return nil, err
	}

	if pointer.Int32Deref(osData.Spec.Replicas, 1) != osData.Status.ReadyReplicas || pointer.Int32Deref(osMaster.Spec.Replicas, 1) != osMaster.Status.ReadyReplicas {
		retResult = &reconcile.Result{
			RequeueAfter: time.Second * 5,
		}
		return
	}

	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := r.client.Get(r.ctx, client.ObjectKeyFromObject(r.opensearchCluster), r.opensearchCluster); err != nil {
			return err
		}
		r.opensearchCluster.Status.Initialized = true
		return r.client.Status().Update(r.ctx, r.opensearchCluster)
	})
	if err != nil {
		return nil, err
	}

	return
}

func (r *Reconciler) ReconcileOpensearchUpgrade() (retResult *reconcile.Result, retErr error) {
	lg := log.FromContext(r.ctx)
	if r.opensearchCluster.Status.Version == nil || *r.opensearchCluster.Status.Version == r.opensearchCluster.Spec.Version {
		return
	}

	// If no persistence and only one data replica we can't safely upgrade so log an error and return
	if r.dataSingleton() {
		lg.Error(ErrOpensearchUpgradeFailed, "insufficient data node persistence")
		return
	}

	if r.masterSingleton() {
		lg.Error(ErrOpensearchUpgradeFailed, "insufficient master node persistence")
		return
	}

	os := NewReconciler(r.ctx, r.client, r.opensearchCluster)

	// Update data nodes first
	requeue, err := os.UpgradeData()
	if err != nil {
		return retResult, err
	}
	if requeue {
		retResult = &reconcile.Result{
			RequeueAfter: 5 * time.Second,
		}
		return
	}

	retErr = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := r.client.Get(r.ctx, client.ObjectKeyFromObject(r.opensearchCluster), r.opensearchCluster); err != nil {
			return err
		}
		r.opensearchCluster.Status.Version = &r.opensearchCluster.Spec.Version
		return r.client.Status().Update(r.ctx, r.opensearchCluster)
	})

	return
}

func (r *Reconciler) OpensearchResources() (resourceList []resources.Resource, _ error) {
	resourceList = append(resourceList, r.internalUsersSecret())
	resourceList = append(resourceList, r.opensearchServices()...)
	resourceList = append(resourceList, r.opensearchConfigSecret())
	resourceList = append(resourceList, r.opensearchWorkloads()...)
	return
}

func (r *Reconciler) masterSingleton() bool {
	return (r.opensearchCluster.Spec.Master.Replicas == nil ||
		*r.opensearchCluster.Spec.Master.Replicas == int32(1)) &&
		(r.opensearchCluster.Spec.Master.Persistence == nil ||
			!r.opensearchCluster.Spec.Master.Persistence.Enabled)
}

func (r *Reconciler) dataSingleton() bool {
	return (r.opensearchCluster.Spec.Data.Replicas == nil ||
		*r.opensearchCluster.Spec.Data.Replicas == int32(1)) &&
		(r.opensearchCluster.Spec.Data.Persistence == nil ||
			!r.opensearchCluster.Spec.Data.Persistence.Enabled)
}
