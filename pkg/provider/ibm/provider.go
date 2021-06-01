package ibm

import (
	"context"
	"fmt"

	"github.com/IBM/go-sdk-core/v5/core"
	sm "github.com/IBM/secrets-manager-go-sdk/secretsmanagerv1"
	esv1alpha1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	"github.com/external-secrets/external-secrets/pkg/provider"
	"github.com/go-logr/logr"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	SecretsManagerEndpointEnv = "IBM_SECRETSMANAGER_ENDPOINT"
	STSEndpointEnv            = "IBM_STS_ENDPOINT"
	SSMEndpointEnv            = "IBM_SSM_ENDPOINT"

	errUnableCreateSession                     = "unable to create session: %w"
	errIBMClient                               = "cannot setup new ibm client: %w"
	errUnknownProviderService                  = "unknown IBM Provider Service: %s"
	errInvalidClusterStoreMissingAKIDNamespace = "invalid ClusterSecretStore: missing IBM AccessKeyID Namespace"
	errInvalidClusterStoreMissingSAKNamespace  = "invalid ClusterSecretStore: missing IBM SecretAccessKey Namespace"
	errFetchAKIDSecret                         = "could not fetch accessKeyID secret: %w"
	errFetchSAKSecret                          = "could not fetch SecretAccessKey secret: %w"
	errMissingSAK                              = "missing SecretAccessKey"
	errMissingAKID                             = "missing AccessKeyID"
	errNilStore                                = "found nil store"
	errMissingStoreSpec                        = "store is missing spec"
	errMissingProvider                         = "storeSpec is missing provider"
	errInvalidProvider                         = "invalid provider spec. Missing IBM field in store %s"
)

type IBMSecretManagerClient interface {
	GetSecret(getSecretOptions *sm.GetSecretOptions) (result *sm.GetSecret, response *core.DetailedResponse, err error)
}

type providerIBM struct {
	IBMClient  IBMSecretManagerClient
	ServiceUrl string
}

type client struct {
	kube      kclient.Client
	store     *esv1alpha1.IBMProvider
	log       logr.Logger
	namespace string
	storeKind string
}

func (ibm *providerIBM) GetSecret(ctx context.Context, ref esv1alpha1.ExternalSecretDataRemoteRef) ([]byte, error) {
	//	if (ibm.client == nil) || ibm.
	return nil, nil
}

func (ibm *providerIBM) GetSecretMap(ctx context.Context, ref esv1alpha1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	return nil, nil
}

func (p *providerIBM) NewClient(ctx context.Context, store esv1alpha1.GenericStore, kube kclient.Client, namespace string) (provider.SecretsClient, error) {
	storeSpec := store.GetSpec()
	ibmSpec := storeSpec.Provider.IBM

	secretsManager, err := sm.NewSecretsManagerV1(&sm.SecretsManagerV1Options{
		URL: *ibmSpec.ServiceURL,
		Authenticator: &core.IamAuthenticator{
			ApiKey: *ibmSpec.Auth.APIKey,
		},
	})
	if err != nil {
		return nil, fmt.Errorf(errIBMClient, err)
	}

	// iStore := &client{
	// 	kube:      kube,
	// 	store:     ibmSpec,
	// 	log:       ctrl.Log.WithName("provider").WithName("ibm"),
	// 	namespace: namespace,
	// 	storeKind: store.GetObjectKind().GroupVersionKind().Kind,
	// }

	// return iStore, nil
	p.IBMClient = secretsManager
	return p, nil
}
