package ibm

import (
	"context"

	"github.com/IBM/go-sdk-core/v5/core"
	sm "github.com/IBM/secrets-manager-go-sdk/secretsmanagerv1"
	"github.com/external-secrets/external-secrets/pkg/provider/aws/session"
	"github.com/go-logr/logr"
)

type provider struct {
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
		panic(err)
	}

	iStore := &client{
		kube:      kube,
		store:     ibmSpec,
		log:       ctrl.Log.WithName("provider").WithName("ibm"),
		namespace: namespace,
		storeKind: store.GetObjectKind().GroupVersionKind().Kind,
	}

	cfg := bluemix.Config{
		//	bluemix.Config.IAMAccessToken:
	}

	session = session.New(&cfg)
}

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