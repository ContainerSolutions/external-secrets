package ibm

import (
	"context"

	"github.com/IBM/go-sdk-core/v5/core"
	sm "github.com/IBM/secrets-manager-go-sdk/secretsmanagerv1"
	"github.com/go-logr/logr"
)


type provider struct {
}

const (
	SecretsManagerEndpointEnv = "IBM_SECRETSMANAGER_ENDPOINT"
	STSEndpointEnv            = "IBM_STS_ENDPOINT"
	SSMEndpointEnv            = "IBM_SSM_ENDPOINT"

	errUnableCreateSession                     = "unable to create session: %w"
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

type client struct {
	kube      kclient.Client
	store     *esv1alpha1.IBMProvider
	log       logr.Logger
	client    Client
	namespace string
	storeKind string
}

func (ibm *client) GetSecret(ctx context.Context, ref esv1alpha1.ExternalSecretDataRemoteRef) ([]byte, error) {


}

func (ibm *client) GetSecretMap(ctx context.Context, ref esv1alpha1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {

}

func (p *provider) NewClient(ctx context.Context, store esv1alpha1.GenericStore, kube kclient.Client, namespace string) (provider.SecretsClient, error) {
	storeSpec := store.GetSpec()
	imbSpec := storeSpec.Provider.IBM

	secretsManager, err := sm.NewSecretsManagerV1(&sm.SecretsManagerV1Options{
		URL: "<SERVICE_URL>",
		Authenticator: &core.IamAuthenticator{
			ApiKey: "<IBM_CLOUD_API_KEY>",
		},
	})

	if err != nil {
		return nil, err
	}

	iStore := &client{
		client:    secretsManager,
		kube:      kube,
		store:     ibmSpec,
		log:       ctrl.Log.WithName("provider").WithName("ibm"),
		namespace: namespace,
		storeKind: store.GetObjectKind().GroupVersionKind().Kind,
	}

	return iStore, nil
}
