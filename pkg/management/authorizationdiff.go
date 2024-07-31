package management

import (
	"github.com/cloudtrust/common-service/v2/configuration"
)

// DiffKey type
type DiffKey int8

const (
	nilString = "<<null>>"

	// Added is a DiffKey telling that an authorization has been added
	Added DiffKey = iota
	// Removed is a DiffKey telling that an authorization has been removed
	Removed DiffKey = iota
)

// Note: An authorization set is a multiple-level map. It is created using a set of keys, each key is matching a level of the map.
// While there are remaining keys, you add a level of maps: in this case, any is another map[string]any.
// When all keys are processed, 'any' matches an instance of a struct, in our case, an instance of configuration.Authorization

func toNonNil(value *string) string {
	if value == nil {
		return nilString
	}
	return *value
}

// insertIntoMap will fill a multi-level map using given keys. Each key will be used at a different level.
// When all keys have been used, the given authorization is stored.
// Let's imagine we are not storing authorization but vehicles and let's consider the following calls:
//
//	insertIntoMap(myVehicles, Vehicle{Type: Car, Brand: Porsche, Color: Blue}, Car, Porsche, Blue)
//	insertIntoMap(myVehicles, Vehicle{Type: Motorbike, Brand: Suzuki, Color: Red}, Motorbike, Suzuki, Red)
//	insertIntoMap(myVehicles, Vehicle{Type: Car, Brand: Ferrari, Color: Red}, Car, Ferrari, Red)
//
// The map result is the following:
// myVehicles
//
//	|
//	+ Car
//	|   |
//	|   + Ferrari
//	|   |   |
//	|   |   + Red
//	|   |       |
//	|   |       + Vehicle{Type: Car, Brand: Ferrari, Color: Red}
//	|   + Porsche
//	|   |   |
//	|   |   + Blue
//	|   |       |
//	|   |       + Vehicle{Type: Car, Brand: Porsche, Color: Blue}
//	+ Motorbike
//	|   |
//	|   + Suzuki
//	|       |
//	|       + Red
//	|           |
//	|           + Vehicle{Type: Motorbike, Brand: Suzuki, Color: Red}
func insertIntoMap(authz map[string]any, auth configuration.Authorization, keys ...string) {
	var subMap any
	if v, ok := authz[keys[0]]; ok {
		// Key already exists... Get the matching sub map
		subMap = v
	} else {
		// Key does not exist yet... Create a sub map
		subMap = map[string]any{}
	}
	if len(keys) > 1 {
		// There are remaining keys: insert auth in subMap using remaining keys (here, any is a map[string]any)
		insertIntoMap(subMap.(map[string]any), auth, keys[1:]...)
		authz[keys[0]] = subMap
	} else {
		// It was the last key: set the auth value (here, any is a configuration.Authorization)
		authz[keys[0]] = auth
	}
}

func toMap(input []configuration.Authorization) map[string]any {
	var authz = make(map[string]any)
	for _, auth := range input {
		// Insert auth in the authz multi-level map using following different level of keys:
		// - realm, group, action, targetRealm, targetGroup
		insertIntoMap(authz, auth, *auth.RealmID, *auth.GroupName, *auth.Action, toNonNil(auth.TargetRealmID), toNonNil(auth.TargetGroupName))
	}
	return authz
}

// Diff computes the difference between 2 lists of authorizations
func Diff(authz1, authz2 []configuration.Authorization) map[DiffKey][]configuration.Authorization {
	var authzSet1 = toMap(authz1)
	var authzSet2 = toMap(authz2)
	var res = make(map[DiffKey][]configuration.Authorization)
	computeDiff(authzSet1, authzSet2, res)
	return res
}

func setAsDifferent(value any, diff map[DiffKey][]configuration.Authorization, diffKey DiffKey) {
	switch v := value.(type) {
	case map[string]any:
		for _, subvalue := range v {
			setAsDifferent(subvalue, diff, diffKey)
		}
	case configuration.Authorization:
		diff[diffKey] = append(diff[diffKey], v)
	}
}

func computeDiff(thisMap map[string]any, otherMap map[string]any, diff map[DiffKey][]configuration.Authorization) {
	for otherKey, otherValue := range otherMap {
		if thisValue, ok := thisMap[otherKey]; !ok {
			// Key exists in other, not in this... Add it
			setAsDifferent(otherValue, diff, Added)
		} else {
			// Key exists in both other and this. Check in sub maps
			switch v := thisValue.(type) {
			case map[string]any:
				computeDiff(v, otherValue.(map[string]any), diff)
			}
			// thisValue is a configuration.Authorization, we assume that thisValue==otherValue
		}
	}
	for thisKey, thisValue := range thisMap {
		if _, ok := otherMap[thisKey]; !ok {
			// Key exists in this, not in other... Remove all authorizations from this
			setAsDifferent(thisValue, diff, Removed)
		}
		// Else would be case where key exists in both thisMap and otherMap... Already processed in first for loop
	}
}
