/*
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

package v1alpha1

import (
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)


// Configures an store to sync secrets using a IBM Cloud Secrets Manager
// backend.
type IBMProvider struct {
	// Auth configures how secret-manager authenticates with the IBM secrets manager.
	Auth IBMAuth `json:"auth"`

	// ServiceURL is the Endpoint URL that is specific to the Secrets Manager service instance
	ServiceURL *string `json:"serviceUrl,omitempty"`
}

// IBMAuth is the configuration used to authenticate with the IBM secrets manager.
type IBMAuth struct {
	// APIKey is used to authenticate to the secrets manager
	APIKey *string `json:"apiKey,omitempty"`
}

// VaultAppRole authenticates with Vault using the App Role auth mechanism,
// with the role and secret stored in a Kubernetes Secret resource.
type VaultAppRole struct {
	// Path where the App Role authentication backend is mounted
	// in Vault, e.g: "approle"
	// +kubebuilder:default=approle
	Path string `json:"path"`

	// RoleID configured in the App Role authentication backend when setting
	// up the authentication backend in Vault.
	RoleID string `json:"roleId"`

	// Reference to a key in a Secret that contains the App Role secret used
	// to authenticate with Vault.
	// The `key` field must be specified and denotes which entry within the Secret
	// resource is used as the app role secret.
	SecretRef esmeta.SecretKeySelector `json:"secretRef"`
}

// Authenticate against Vault using a Kubernetes ServiceAccount token stored in
// a Secret.
type VaultKubernetesAuth struct {
	// Path where the Kubernetes authentication backend is mounted in Vault, e.g:
	// "kubernetes"
	// +kubebuilder:default=kubernetes
	Path string `json:"mountPath"`

	// Optional service account field containing the name of a kubernetes ServiceAccount.
	// If the service account is specified, the service account secret token JWT will be used
	// for authenticating with Vault. If the service account selector is not supplied,
	// the secretRef will be used instead.
	// +optional
	ServiceAccountRef *esmeta.ServiceAccountSelector `json:"serviceAccountRef,omitempty"`

	// Optional secret field containing a Kubernetes ServiceAccount JWT used
	// for authenticating with Vault. If a name is specified without a key,
	// `token` is the default. If one is not specified, the one bound to
	// the controller will be used.
	// +optional
	SecretRef *esmeta.SecretKeySelector `json:"secretRef,omitempty"`

	// A required field containing the Vault Role to assume. A Role binds a
	// Kubernetes ServiceAccount with a set of Vault policies.
	Role string `json:"role"`
}

// VaultLdapAuth authenticates with Vault using the LDAP authentication method,
// with the username and password stored in a Kubernetes Secret resource.
type VaultLdapAuth struct {
	// Username is a LDAP user name used to authenticate using the LDAP Vault
	// authentication method
	Username string `json:"username"`

	// SecretRef to a key in a Secret resource containing password for the LDAP
	// user used to authenticate with Vault using the LDAP authentication
	// method
	SecretRef esmeta.SecretKeySelector `json:"secretRef,omitempty"`
}

// VaultJwtAuth authenticates with Vault using the JWT/OIDC authentication
// method, with the role name and token stored in a Kubernetes Secret resource.
type VaultJwtAuth struct {
	// Role is a JWT role to authenticate using the JWT/OIDC Vault
	// authentication method
	// +optional
	Role string `json:"role"`

	// SecretRef to a key in a Secret resource containing JWT token to
	// authenticate with Vault using the JWT/OIDC authentication method
	SecretRef esmeta.SecretKeySelector `json:"secretRef,omitempty"`
}
