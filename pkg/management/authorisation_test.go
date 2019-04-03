package management

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestMarshallAuthorisations(t *testing.T) {

	var authz = make(map[string]map[string]map[string]map[string]map[string]struct{})

	authz["master"] = make(map[string]map[string]map[string]map[string]struct{})
	authz["master"]["toe"] = make(map[string]map[string]map[string]struct{})
	authz["master"]["toe"]["priv1"] = make(map[string]map[string]struct{})
	authz["master"]["toe"]["priv1"]["master"] = make(map[string]struct{})
	authz["master"]["toe"]["priv1"]["master"]["l1"] = struct{}{}

	res, _ := json.Marshal(authz)

	fmt.Println(string(res))
}

func TestLoadAuthorisations(t *testing.T) {

	const jsonAuthz = `{"master":{"toe":{"priv1":{"master":{"l1":{}}}}}}`

	var authz = make(map[string]map[string]map[string]map[string]map[string]struct{})

	err := json.Unmarshal([]byte(jsonAuthz), &authz)

	if err != nil {
		fmt.Println(string(err.Error()))
	}

	fmt.Println("OK")

	fmt.Println(len(authz))
	fmt.Println(len(authz["master"]))
	fmt.Println(len(authz["master2"]))
	fmt.Println(authz)

	_, ok := authz["master"]["toe"]["priv1"]["master"]["l1"]
	fmt.Println(ok)

	_, ok = authz["master"]["toe"]["priv1"]["master"]["l2"]
	fmt.Println(ok)

	_, ok = authz["master2"]["toe"]["priv1"]["master"]["l1"]
	fmt.Println(ok)

}

func TestLoadAuthorisations2(t *testing.T) {

	jsonAuthz, err := ioutil.ReadFile("/cloudtrust/go/src/github.com/cloudtrust/keycloak-bridge/configs/authorization-test.yml")

	if err != nil {
		return 
	}

	var authz = make(Authorizations)

	if err = json.Unmarshal(jsonAuthz, &authz); err != nil {
		fmt.Println("Error "+ err.Error())
		return 
	}

	return 

}
