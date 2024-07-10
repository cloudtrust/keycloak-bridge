package management

import (
	"sort"
	"strings"
	"testing"

	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/stretchr/testify/assert"
)

func sortAuthz(authz []configuration.Authorization) {
	sort.Slice(authz, func(i, j int) bool {
		var item1 = authz[i]
		var item2 = authz[j]
		var cmp = strings.Compare(*item1.RealmID, *item2.RealmID)
		if cmp == 0 {
			cmp = strings.Compare(*item1.GroupName, *item2.GroupName)
			if cmp == 0 {
				cmp = strings.Compare(*item1.Action, *item2.Action)
				if cmp == 0 {
					cmp = strings.Compare(toNonNil(item1.TargetRealmID), toNonNil(item2.TargetRealmID))
					if cmp == 0 {
						cmp = strings.Compare(toNonNil(item1.TargetGroupName), toNonNil(item2.TargetGroupName))
					}
				}
			}
		}
		return cmp < 0
	})
}

func TestAuthorizationSetApply(t *testing.T) {
	var test = func(t *testing.T, inputSet1, inputSet2, expectedSet1, expectedSet2 []configuration.Authorization) {
		var diff = Diff(inputSet1, inputSet2)
		if addAuthz, ok := diff[Added]; ok {
			// Sort slice for assert.Equal to be able to compare them
			sortAuthz(addAuthz)
			assert.Equal(t, expectedSet1, addAuthz)
		} else {
			assert.Len(t, expectedSet1, 0)
		}
		if delAuthz, ok := diff[Removed]; ok {
			sortAuthz(delAuthz)
			assert.Equal(t, expectedSet2, delAuthz)
		} else {
			assert.Len(t, expectedSet2, 0)
		}
	}

	var authz = []configuration.Authorization{
		{RealmID: ptr("realm11"), GroupName: ptr("group11"), Action: ptr("action1"), TargetRealmID: ptr("realm21"), TargetGroupName: ptr("group21")},
		{RealmID: ptr("realm11"), GroupName: ptr("group11"), Action: ptr("action2"), TargetRealmID: ptr("realm22"), TargetGroupName: ptr("group22")},
		{RealmID: ptr("realm11"), GroupName: ptr("group12"), Action: ptr("action1"), TargetRealmID: ptr("realm21"), TargetGroupName: ptr("group21")},
		{RealmID: ptr("realm31"), GroupName: ptr("group11"), Action: ptr("action3"), TargetRealmID: ptr("realm23"), TargetGroupName: ptr("group22")},
	}
	var emptySet = []configuration.Authorization{}

	t.Run("Nothing to add, remove one auth", func(t *testing.T) {
		var set1 = []configuration.Authorization{authz[0], authz[1]}
		var set2 = []configuration.Authorization{authz[1]}
		test(t, set1, set2, []configuration.Authorization{}, []configuration.Authorization{set1[0]})
	})
	t.Run("Remove all", func(t *testing.T) {
		var set1 = []configuration.Authorization{authz[0], authz[1]}
		var set2 = []configuration.Authorization{}
		test(t, set1, set2, emptySet, set1)
	})
	t.Run("Add new realm", func(t *testing.T) {
		var set1 = []configuration.Authorization{authz[0], authz[1]}
		test(t, []configuration.Authorization{}, set1, set1, emptySet)
	})
	t.Run("Add new group", func(t *testing.T) {
		var set1 = []configuration.Authorization{authz[0]}
		var set2 = []configuration.Authorization{authz[0], authz[2]}
		test(t, set1, set2, []configuration.Authorization{authz[2]}, emptySet)
	})
}
