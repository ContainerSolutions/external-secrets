/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
limitations under the License.
*/
package azure

import (
	"context"
	"fmt"
	"os"

	// nolint
	. "github.com/onsi/ginkgo"
	// nolint
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	esv1alpha1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/external-secrets/external-secrets/e2e/framework"
)

const (
	targetSecret = "target-secret"
)

var _ = Describe("[azure] ", func() {
	f := framework.New("eso-azure")
	var secretStore *esv1alpha1.SecretStore
	vaultURL := os.Getenv("VAULT_URL")
	tenantID := os.Getenv("TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	BeforeEach(func() {
		By("creating a secret in AzureKV")
		azureCreds := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      f.Namespace.Name,
				Namespace: f.Namespace.Name,
			},
			StringData: map[string]string{
				"ClientID":     clientID,
				"ClientSecret": clientSecret,
			},
		}
		err := f.CRClient.Create(context.Background(), azureCreds)
		Expect(err).ToNot(HaveOccurred())
		secretStore = &esv1alpha1.SecretStore{
			ObjectMeta: metav1.ObjectMeta{
				Name:      f.Namespace.Name,
				Namespace: f.Namespace.Name,
			},
			Spec: esv1alpha1.SecretStoreSpec{
				Provider: &esv1alpha1.SecretStoreProvider{
					AzureKV: &esv1alpha1.AzureKVProvider{
						TenantID: &tenantID,
						VaultURL: &vaultURL,
						AuthSecretRef: &esv1alpha1.AzureKVAuth{
							ClientID: &esmeta.SecretKeySelector{
								Name: f.Namespace.Name,
								Key:  "ClientID",
							},
							ClientSecret: &esmeta.SecretKeySelector{
								Name: f.Namespace.Name,
								Key:  "ClientSecret",
							},
						},
					},
				},
			},
		}
		err = f.CRClient.Create(context.Background(), secretStore)
		Expect(err).ToNot(HaveOccurred())
	})

	It("should sync secrets", func() {
		By("creating a AzureKV Secret")
		secretKey1 := fmt.Sprintf("%s-%s", f.Namespace.Name, "one")
		secretValue := "great-value-test"
		_, err := createAzureKVSecret(
			secretKey1,
			secretValue,
			clientID,
			clientSecret,
			tenantID,
			vaultURL)
		Expect(err).ToNot(HaveOccurred())
		err = f.CRClient.Create(context.Background(), &esv1alpha1.ExternalSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "simple-sync",
				Namespace: f.Namespace.Name,
			},
			Spec: esv1alpha1.ExternalSecretSpec{
				SecretStoreRef: esv1alpha1.SecretStoreRef{
					Name: f.Namespace.Name,
				},
				Target: esv1alpha1.ExternalSecretTarget{
					Name: targetSecret,
				},
				Data: []esv1alpha1.ExternalSecretData{
					{
						SecretKey: secretKey1,
						RemoteRef: esv1alpha1.ExternalSecretDataRemoteRef{
							Key: secretKey1,
						},
					},
				},
			},
		})
		Expect(err).ToNot(HaveOccurred())

		_, err = f.WaitForSecretValue(f.Namespace.Name, targetSecret, map[string][]byte{
			secretKey1: []byte(secretValue),
		})
		Expect(err).ToNot(HaveOccurred())

		err = deleteAzureKVSecret(secretKey1, clientID, clientSecret, tenantID, vaultURL)
		Expect(err).ToNot(HaveOccurred())
	})

})
