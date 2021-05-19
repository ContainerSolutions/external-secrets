package ibm

import (
  sm "github.com/IBM/secrets-manager-go-sdk/ibm-cloud-secrets-manager-api-v1"
)

type provider struct {

}

func (p *provider) NewClient(ctx context.Context, store esv1alpha1.GenericStore, kube kclient.Client, namespace string) (provider.SecretsClient, error) {
	storeSpec := store.GetSpec()
    imbSpec := storeSpec.Provider.IBM

	iStore := &client{
		kube:      kube,
		store:     ibmSpec,
		log:       ctrl.Log.WithName("provider").WithName("ibm"),
		namespace: namespace,
		storeKind: store.GetObjectKind().GroupVersionKind().Kind,
	}

	cfg := bluemix.Config{
		bluemix.Config.IAMAccessToken: 
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