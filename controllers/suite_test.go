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
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/kralicky/kmatch"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/phayes/freeport"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/rancher/opni-opensearch-operator/pkg/test"
	"github.com/rancher/opni/pkg/util"
	//+kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var (
	k8sClient  client.Client
	k8sManager ctrl.Manager
	testEnv    *envtest.Environment
	stopEnv    context.CancelFunc
)

func TestAPIs(t *testing.T) {
	SetDefaultEventuallyTimeout(45 * time.Second)
	// SetDefaultEventuallyTimeout(24 * time.Hour) // For debugging
	SetDefaultEventuallyPollingInterval(100 * time.Millisecond)
	SetDefaultConsistentlyDuration(2 * time.Second)
	SetDefaultConsistentlyPollingInterval(100 * time.Millisecond)
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(util.NewTestLogger())
	port, err := freeport.GetFreePort()
	Expect(err).NotTo(HaveOccurred())

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		BinaryAssetsDirectory: "../testbin/bin",
		ControlPlane: envtest.ControlPlane{
			APIServer: &envtest.APIServer{
				SecureServing: envtest.SecureServing{
					ListenAddr: envtest.ListenAddr{
						Address: "127.0.0.1",
						Port:    fmt.Sprint(port),
					},
				},
			},
		},
	}

	stopEnv, k8sManager, k8sClient = test.RunTestEnvironment(testEnv, true, false,
		&OpensearchClusterReconciler{},
		&DashboardsReconciler{},
	)
	kmatch.SetDefaultObjectClient(k8sClient)
})

func makeTestNamespace() string {
	for i := 0; i < 100; i++ {
		ns := fmt.Sprintf("test-%d", i)
		if err := k8sClient.Create(
			context.Background(),
			&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: ns,
					Annotations: map[string]string{
						"controller-test": "true",
					},
				},
			},
		); err != nil {
			continue
		}
		return ns
	}
	panic("could not create namespace")
}

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	stopEnv()
	test.ExternalResources.Wait()
})

func updateObject(existing client.Object, patchFn interface{}) {
	patchFnValue := reflect.ValueOf(patchFn)
	if patchFnValue.Kind() != reflect.Func {
		panic("patchFn must be a function")
	}
	var lastErr error
	waitErr := wait.ExponentialBackoff(wait.Backoff{
		Duration: 10 * time.Millisecond,
		Factor:   2,
		Steps:    10,
	}, func() (bool, error) {
		// Make a copy of the existing object
		existingCopy := existing.DeepCopyObject().(client.Object)
		// Get the latest version of the object
		lastErr = k8sClient.Get(context.Background(),
			client.ObjectKeyFromObject(existingCopy), existingCopy)
		if lastErr != nil {
			return false, nil
		}
		// Call the patchFn to make changes to the object
		patchFnValue.Call([]reflect.Value{reflect.ValueOf(existingCopy)})
		// Apply the patch
		lastErr = k8sClient.Update(context.Background(), existingCopy, &client.UpdateOptions{})
		if lastErr != nil {
			return false, nil
		}
		// Replace the existing object with the new one
		existing = existingCopy
		return true, nil // exit backoff loop
	})
	if waitErr != nil {
		Fail("failed to update object: " + lastErr.Error())
	}
}
