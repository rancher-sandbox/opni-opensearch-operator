package controllers

import (
	"context"
	"fmt"

	. "github.com/kralicky/kmatch"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rancher/opni-opensearch-operator/api/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
)

var _ = Describe("OpensearchCluster Controller", Label("controller"), func() {
	dashboards := &v1beta1.Dashboards{}

	It("should successfully create a dashboards", func() {
		testNamespace := makeTestNamespace()
		osCluster := &v1beta1.OpensearchCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cluster",
				Namespace: testNamespace,
			},
			Spec: v1beta1.OpensearchClusterSpec{
				Version: "1.0.0",
			},
		}
		dashboards = &v1beta1.Dashboards{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-dashboards",
				Namespace: testNamespace,
			},
			Spec: v1beta1.DashboardsSpec{
				Version: "1.0.0",
				OpensearchCluster: &corev1.LocalObjectReference{
					Name: "test-cluster",
				},
				NodeSelector: map[string]string{
					"foo": "bar",
				},
				Tolerations: []corev1.Toleration{
					{
						Key:      "foo",
						Operator: corev1.TolerationOpExists,
					},
				},
			},
		}

		Expect(k8sClient.Create(context.Background(), osCluster)).To(Succeed())
		Expect(k8sClient.Create(context.Background(), dashboards)).To(Succeed())
	})

	It("should create the workloads", func() {
		Eventually(Object(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-dashboards-os-dashboards",
				Namespace: dashboards.Namespace,
			},
		})).Should(ExistAnd(
			HaveOwner(dashboards),
			HaveLabels(
				"app", "opensearch",
				"role", "dashboards",
			),
			HaveReplicaCount(1),
			HaveNodeSelector("foo", "bar"),
			HaveTolerations("foo"),
			HaveMatchingContainer(And(
				HaveName("dashboards"),
				HaveImage("docker.io/opensearchproject/opensearch-dashboards:1.0.0"),
				HaveEnv(
					"OPENSEARCH_HOSTS", fmt.Sprintf("https://test-cluster-os-client.%s:9200", dashboards.Namespace),
				),
				HavePorts("http"),
			)),
		))
	})
	It("should create the service", func() {
		Eventually(Object(&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-dashboards-os-dashboards",
				Namespace: dashboards.Namespace,
			},
		})).Should(ExistAnd(
			HaveOwner(dashboards),
		))
	})
	It("should update the replica counts", func() {
		updateObject(dashboards, func(obj *v1beta1.Dashboards) {
			obj.Spec.Replicas = pointer.Int32(2)
		})
		Eventually(Object(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-dashboards-os-dashboards",
				Namespace: dashboards.Namespace,
			},
		})).Should(HaveReplicaCount(2))
	})
	It("should remove the resources when deleted", func() {
		Expect(k8sClient.Delete(context.Background(), dashboards)).To(Succeed())

		Eventually(Object(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-dashboards-os-dashboards",
				Namespace: dashboards.Namespace,
			},
		})).ShouldNot(Exist())

		Eventually(Object(&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-dashboards-os-dashboards",
				Namespace: dashboards.Namespace,
			},
		})).ShouldNot(Exist())
	})
})
