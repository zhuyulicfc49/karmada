/*
Copyright 2026 The Karmada Authors.

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

package base

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	kindexec "sigs.k8s.io/kind/pkg/exec"
	"sigs.k8s.io/controller-runtime/pkg/client"

	clusterv1alpha1 "github.com/karmada-io/karmada/pkg/apis/cluster/v1alpha1"
	policyv1alpha1 "github.com/karmada-io/karmada/pkg/apis/policy/v1alpha1"
	"github.com/karmada-io/karmada/test/e2e/framework"
	testhelper "github.com/karmada-io/karmada/test/helper"
)

// Push-mode token rotation: proves informers recover after the member cluster
// bearer token rotates — the fix for karmada-io/karmada#7562.
//
// The test forces a watch reconnection by restarting the member cluster's kind
// container (docker restart). This is necessary because an open watch survives
// token revocation — the API server only re-validates auth on reconnection.
var _ = framework.SerialDescribe("push-mode token rotation", func() {
	var (
		targetCluster  string
		deploymentNS   string
		deploymentName string
		deployment     *appsv1.Deployment
		policy         *policyv1alpha1.PropagationPolicy
	)

	ginkgo.BeforeEach(func() {
		pushClusters := framework.ClusterNamesWithSyncMode(clusterv1alpha1.Push)
		gomega.Expect(pushClusters).ShouldNot(gomega.BeEmpty(), "need at least one push-mode cluster")
		targetCluster = pushClusters[0]

		deploymentNS = testNamespace
		deploymentName = deploymentNamePrefix + rand.String(RandomStrLength)
		deployment = testhelper.NewDeployment(deploymentNS, deploymentName)

		policy = testhelper.NewPropagationPolicy(deploymentNS, deploymentName, []policyv1alpha1.ResourceSelector{
			{APIVersion: deployment.APIVersion, Kind: deployment.Kind, Name: deployment.Name},
		}, policyv1alpha1.Placement{
			ClusterAffinity: &policyv1alpha1.ClusterAffinity{
				ClusterNames: []string{targetCluster},
			},
		})
	})

	ginkgo.JustBeforeEach(func() {
		framework.CreatePropagationPolicy(karmadaClient, policy)
		framework.CreateDeployment(kubeClient, deployment)
		ginkgo.DeferCleanup(func() {
			framework.RemoveDeployment(kubeClient, deployment.Namespace, deployment.Name)
			framework.RemovePropagationPolicy(karmadaClient, policy.Namespace, policy.Name)
		})
	})

	ginkgo.It("informers recover after member cluster token rotates", func() {
		ginkgo.By("1. verify workload propagated and status collected (baseline)", func() {
			framework.WaitDeploymentPresentOnClusterFitWith(targetCluster, deploymentNS, deploymentName,
				func(d *appsv1.Deployment) bool {
					return d.Status.ReadyReplicas > 0
				})
			klog.Infof("baseline: deployment %s/%s present on %s with ready replicas", deploymentNS, deploymentName, targetCluster)
		})

		// Get Cluster CR and Secret reference.
		cluster := &clusterv1alpha1.Cluster{}
		gomega.Expect(controlPlaneClient.Get(context.TODO(), client.ObjectKey{Name: targetCluster}, cluster)).Should(gomega.Succeed())
		gomega.Expect(cluster.Spec.SecretRef).ShouldNot(gomega.BeNil())
		secretNS := cluster.Spec.SecretRef.Namespace
		secretName := cluster.Spec.SecretRef.Name

		// Read Secret to find the SA.
		secret := &corev1.Secret{}
		gomega.Expect(controlPlaneClient.Get(context.TODO(), client.ObjectKey{Namespace: secretNS, Name: secretName}, secret)).Should(gomega.Succeed())
		saNamespace, saName := parseSAFromToken(string(secret.Data["token"]))
		klog.Infof("cluster %s uses SA %s/%s on the member", targetCluster, saNamespace, saName)

		memberClient := framework.GetClusterClient(targetCluster)
		gomega.Expect(memberClient).ShouldNot(gomega.BeNil())

		ginkgo.By("2. rotate: revoke old token, mint new, write to Secret", func() {
			// CORRECT ORDER: revoke first → mint second (new token bound to new SA UID)
			gomega.Expect(memberClient.CoreV1().ServiceAccounts(saNamespace).Delete(
				context.TODO(), saName, metav1.DeleteOptions{})).Should(gomega.Succeed())
			_, err := memberClient.CoreV1().ServiceAccounts(saNamespace).Create(
				context.TODO(), &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
					Name: saName, Namespace: saNamespace,
				}}, metav1.CreateOptions{})
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
			klog.Infof("revoked old tokens by recreating SA %s/%s", saNamespace, saName)

			// Mint new token bound to the recreated SA (new UID).
			tokenReq := &authenticationv1.TokenRequest{
				Spec: authenticationv1.TokenRequestSpec{
					ExpirationSeconds: ptr.To[int64](86400),
				},
			}
			tokenResp, err := memberClient.CoreV1().ServiceAccounts(saNamespace).CreateToken(
				context.TODO(), saName, tokenReq, metav1.CreateOptions{})
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
			newToken := tokenResp.Status.Token
			klog.Infof("minted new token bound to recreated SA %s/%s", saNamespace, saName)

			// Write new token to the Karmada Secret.
			secret.Data["token"] = []byte(newToken)
			gomega.Expect(controlPlaneClient.Update(context.TODO(), secret)).Should(gomega.Succeed())
			klog.Infof("wrote rotated token to Secret %s/%s", secretNS, secretName)

			// Wait for revocation to take effect (~12s apiserver SA cache).
			klog.Info("waiting for revocation cache to flush...")
			time.Sleep(15 * time.Second)
		})

		ginkgo.By("3. force watch reconnection (docker restart member node)", func() {
			// An open watch survives token revocation. We must kill the TCP connection
			// so the informer is forced to reconnect (and re-authenticate).
			containerName := targetCluster + "-control-plane"
			klog.Infof("restarting kind container %s to force watch reconnection", containerName)

			cmd := kindexec.Command("docker", "restart", containerName)
			output, err := kindexec.CombinedOutputLines(cmd)
			if err != nil {
				klog.Warningf("docker restart failed (output: %v): %v — skipping e2e", output, err)
				ginkgo.Skip("cannot force watch reconnection via docker restart — run manual test instead")
			}
			klog.Infof("container %s restarted", containerName)

			// Wait for member to come back and cluster to be Ready.
			gomega.Eventually(func() bool {
				c := &clusterv1alpha1.Cluster{}
				if err := controlPlaneClient.Get(context.TODO(), client.ObjectKey{Name: targetCluster}, c); err != nil {
					return false
				}
				for _, cond := range c.Status.Conditions {
					if cond.Type == "Ready" && cond.Status == "True" {
						return true
					}
				}
				return false
			}, 90*time.Second, 2*time.Second).Should(gomega.BeTrue(),
				"cluster must return to Ready after container restart")
			klog.Info("cluster Ready again — watch must now re-establish with the (potentially stale) token")
		})

		ginkgo.By("4. verify short-lived path still works (cluster stays Ready)", func() {
			gomega.Consistently(func() bool {
				c := &clusterv1alpha1.Cluster{}
				if err := controlPlaneClient.Get(context.TODO(), client.ObjectKey{Name: targetCluster}, c); err != nil {
					return false
				}
				for _, cond := range c.Status.Conditions {
					if cond.Type == "Ready" && cond.Status == "True" {
						return true
					}
				}
				return false
			}, 30*time.Second, 5*time.Second).Should(gomega.BeTrue(),
				"cluster must remain Ready (short-lived health check unaffected)")
			klog.Info("short-lived path: cluster stayed Ready throughout")
		})

		ginkgo.By("5. verify long-lived path recovered (informer sees member changes)", func() {
			// Scale THROUGH Karmada (not directly on member — Karmada would revert it).
			karmadaDep, err := kubeClient.AppsV1().Deployments(deploymentNS).Get(
				context.TODO(), deploymentName, metav1.GetOptions{})
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
			targetReplicas := *karmadaDep.Spec.Replicas + 2
			karmadaDep.Spec.Replicas = &targetReplicas
			_, err = kubeClient.AppsV1().Deployments(deploymentNS).Update(
				context.TODO(), karmadaDep, metav1.UpdateOptions{})
			gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
			klog.Infof("scaled deployment to %d via Karmada control plane", targetReplicas)

			// Assert Karmada's COLLECTED status reaches the target.
			// This can only happen if the informer reconnected successfully.
			gomega.Eventually(func() bool {
				dep, err := kubeClient.AppsV1().Deployments(deploymentNS).Get(
					context.TODO(), deploymentName, metav1.GetOptions{})
				if err != nil {
					return false
				}
				klog.Infof("karmada collected readyReplicas=%d (target %d)",
					dep.Status.ReadyReplicas, targetReplicas)
				return dep.Status.ReadyReplicas == targetReplicas
			}, 120*time.Second, 5*time.Second).Should(gomega.BeTrue(),
				"Karmada must observe the scaled status after rotation (informer recovered)")
			klog.Info("long-lived path: informer recovered — Karmada sees member status")
		})
	})
})

// parseSAFromToken extracts the ServiceAccount namespace and name from a K8s bound token JWT.
func parseSAFromToken(token string) (namespace, name string) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", ""
	}
	// sub format: "system:serviceaccount:<namespace>:<name>"
	segments := strings.Split(claims.Sub, ":")
	if len(segments) != 4 {
		return "", ""
	}
	return segments[2], segments[3]
}

