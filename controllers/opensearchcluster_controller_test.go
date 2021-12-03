package controllers

import (
	"context"
	"sync"

	. "github.com/kralicky/kmatch"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rancher/opni-opensearch-operator/api/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
)

var _ = Describe("OpensearchCluster Controller", Label("controller"), func() {
	osCluster := &v1beta1.OpensearchCluster{}

	It("should successfully create a cluster", func() {
		testNamespace := makeTestNamespace()
		osCluster = &v1beta1.OpensearchCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cluster",
				Namespace: testNamespace,
			},
			Spec: v1beta1.OpensearchClusterSpec{
				Version: "1.0.0",
				Master: v1beta1.OpensearchWorkloadOptions{
					Replicas: pointer.Int32(3),
					Persistence: &v1beta1.PersistenceSpec{
						Enabled:          true,
						StorageClassName: pointer.String("test-storageclass"),
						Request:          resource.MustParse("5Gi"),
					},
				},
				Data: v1beta1.OpensearchWorkloadOptions{
					Replicas: pointer.Int32(2),
					Persistence: &v1beta1.PersistenceSpec{
						Enabled:          true,
						StorageClassName: pointer.String("test-storageclass"),
						Request:          resource.MustParse("15Gi"),
					},
				},
				Client: v1beta1.OpensearchWorkloadOptions{
					Replicas: pointer.Int32(1),
					NodeSelector: map[string]string{
						"baz": "bat",
					},
					Tolerations: []corev1.Toleration{
						{
							Key:      "bar",
							Operator: corev1.TolerationOpExists,
						},
					},
				},
				GlobalNodeSelector: map[string]string{
					"foo": "bar",
				},
				GlobalTolerations: []corev1.Toleration{
					{
						Key:      "foo",
						Operator: corev1.TolerationOpExists,
					},
				},
			},
		}
		Expect(k8sClient.Create(context.Background(), osCluster)).To(Succeed())
	})
	It("should create the opensearch workloads", func() {
		wg := sync.WaitGroup{}
		wg.Add(3)
		go func() {
			defer GinkgoRecover()
			defer wg.Done()
			Eventually(Object(&appsv1.StatefulSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster-os-master",
					Namespace: osCluster.Namespace,
				},
			})).Should(ExistAnd(
				HaveOwner(osCluster),
				HaveLabels(
					"app", "opensearch",
					"role", "master",
				),
				HaveReplicaCount(3),
				HaveNodeSelector("foo", "bar"),
				HaveTolerations("foo"),
				HaveMatchingVolume(And(
					HaveName("config"),
					HaveVolumeSource("Secret"),
				)),
				HaveMatchingVolume(And(
					HaveName("internalusers"),
					HaveVolumeSource("Secret"),
				)),
				HaveMatchingContainer(And(
					HaveName("opensearch"),
					HaveImage("docker.io/opensearchproject/opensearch:1.0.0"),
					HaveEnv("node.master", "true"),
					HavePorts("transport", "http", "metrics", "rca"),
					HaveVolumeMounts("config", "opensearch-data"),
					HaveVolumeMounts("internalusers", "test-cluster-os-internalusers"),
				)),
				HaveMatchingPersistentVolume(And(
					HaveName("opensearch-data"),
					HaveStorageClass("test-storageclass"),
				)),
			))
		}()
		go func() {
			defer GinkgoRecover()
			defer wg.Done()
			Eventually(Object(&appsv1.StatefulSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster-os-data",
					Namespace: osCluster.Namespace,
				},
			})).Should(ExistAnd(
				HaveOwner(osCluster),
				HaveLabels(
					"app", "opensearch",
					"role", "data",
				),
				HaveReplicaCount(2),
				HaveNodeSelector("foo", "bar"),
				HaveTolerations("foo"),
				HaveMatchingContainer(And(
					HaveName("opensearch"),
					HaveImage("docker.io/opensearchproject/opensearch:1.0.0"),
					HaveEnv(
						"node.data", "true",
						"node.ingest", "true",
						"discovery.zen.minimum_master_nodes", "2",
					),
					HavePorts("transport"),
					HaveVolumeMounts("config", "opensearch-data"),
					HaveVolumeMounts("internalusers", "test-cluster-os-internalusers"),
				)),
				HaveMatchingPersistentVolume(And(
					HaveName("opensearch-data"),
					HaveStorageClass("test-storageclass"),
				)),
				HaveMatchingVolume(And(
					HaveName("internalusers"),
					HaveVolumeSource("Secret"),
				)),
			))
		}()
		go func() {
			defer GinkgoRecover()
			defer wg.Done()
			Eventually(Object(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster-os-client",
					Namespace: osCluster.Namespace,
				},
			})).Should(ExistAnd(
				HaveOwner(osCluster),
				HaveLabels(
					"app", "opensearch",
					"role", "client",
				),
				HaveReplicaCount(1),
				HaveNodeSelector("baz", "bat"),
				HaveTolerations("foo", "bar"),
				HaveMatchingContainer(And(
					HaveName("opensearch"),
					HaveImage("docker.io/opensearchproject/opensearch:1.0.0"),
					HavePorts("transport", "http", "metrics", "rca"),
					HaveVolumeMounts("config"),
					HaveVolumeMounts("internalusers", "test-cluster-os-internalusers"),
					Not(HaveVolumeMounts("opensearch-data")),
				)),
				HaveMatchingVolume(And(
					HaveName("internalusers"),
					HaveVolumeSource("Secret"),
				)),
			))
		}()
		wg.Wait()
	})
	It("should create the opensearch services", func() {
		services := []string{"test-cluster-os-data", "test-cluster-os-client", "test-cluster-os-discovery"}
		for _, svc := range services {
			Eventually(Object(&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      svc,
					Namespace: osCluster.Namespace,
				},
			})).Should(ExistAnd(
				HaveOwner(osCluster),
			))
		}
	})
	It("should create the opensearch secrets", func() {
		Eventually(Object(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cluster-os-config",
				Namespace: osCluster.Namespace,
			},
		})).Should(ExistAnd(
			HaveOwner(osCluster),
			HaveData("logging.yml", nil),
		))
		Eventually(Object(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cluster-os-password",
				Namespace: osCluster.Namespace,
			},
		})).Should(ExistAnd(
			HaveOwner(osCluster),
			HaveData("password", nil),
		))
		Eventually(Object(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cluster-os-internalusers",
				Namespace: osCluster.Namespace,
			},
		})).Should(ExistAnd(
			HaveOwner(osCluster),
			HaveData("internal_users.yml", nil),
		))
	})
	It("should update the replica counts", func() {
		updateObject(osCluster, func(obj *v1beta1.OpensearchCluster) {
			obj.Spec.Data.Replicas = pointer.Int32(1)
			obj.Spec.Master.Replicas = pointer.Int32(1)
		})
		Eventually(Object(&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cluster-os-data",
				Namespace: osCluster.Namespace,
			},
		})).Should(HaveReplicaCount(1))
		Eventually(Object(&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cluster-os-master",
				Namespace: osCluster.Namespace,
			},
		})).Should(HaveReplicaCount(1))
	})
	It("should remove the resources when deleted", func() {
		Expect(k8sClient.Delete(context.Background(), osCluster)).To(Succeed())

		statefulSets := []string{"test-cluster-os-data", "test-cluster-os-master"}
		for _, name := range statefulSets {
			Eventually(Object(&appsv1.StatefulSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: osCluster.Namespace,
				},
			})).ShouldNot(Exist())
		}

		Eventually(Object(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cluster-os-client",
				Namespace: osCluster.Namespace,
			},
		})).ShouldNot(Exist())

		services := []string{"test-cluster-os-data", "test-cluster-os-client", "test-cluster-os-discovery"}
		for _, name := range services {
			Eventually(Object(&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: osCluster.Namespace,
				},
			})).ShouldNot(Exist())
		}

		secrets := []string{"test-cluster-os-config", "test-cluster-os-password", "test-cluster-os-internalusers"}
		for _, name := range secrets {
			Eventually(Object(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: osCluster.Namespace,
				},
			})).ShouldNot(Exist())
		}
	})
})
