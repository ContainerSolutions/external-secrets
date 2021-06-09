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
package fake

import (
	"fmt"

	"github.com/IBM/go-sdk-core/v5/core"
	sm "github.com/IBM/secrets-manager-go-sdk/secretsmanagerv1"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

type IBMMockClient struct {
	getSecret func(getSecretOptions *sm.GetSecretOptions) (result *sm.GetSecret, response *core.DetailedResponse, err error)
}

func (mc *IBMMockClient) GetSecret(getSecretOptions *sm.GetSecretOptions) (result *sm.GetSecret, response *core.DetailedResponse, err error) {
	fmt.Println("MOCK GETSECRRRRT")
	return mc.getSecret(getSecretOptions)
}

func (mc *IBMMockClient) WithValue(req *sm.GetSecretOptions, val *sm.GetSecret, err error) {
	mc.getSecret = func(paramReq *sm.GetSecretOptions) (*sm.GetSecret, *core.DetailedResponse, error) {
		// type secretmanagerpb.AccessSecretVersionRequest contains unexported fields
		// use cmpopts.IgnoreUnexported to ignore all the unexported fields in the cmp.
		fmt.Println("INSIDE WITHVALUE")
		if !cmp.Equal(paramReq, req, cmpopts.IgnoreUnexported(sm.GetSecret{})) {
			return nil, nil, fmt.Errorf("unexpected test argument")
		}
		return val, nil, err
	}
}
