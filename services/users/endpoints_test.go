package users

import (
	"testing"
	"context"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/assert"
	"io"
)

func Test_GetUsers(t *testing.T) {
	var namesInit = [3]string{"john", "paul", "james"}
	var getUsersService = NewMockService(namesInit[:])
	var getUsersEndpoint = MakeGetUsersEndpoint(getUsersService)
	var getUsersEndpoints = &Endpoints{
		GetUsersEndpoint:getUsersEndpoint,
	}
	resultc, errc := getUsersEndpoints.GetUsers(context.Background(), "master")
	var names [3]string
	loop:for i:=0; i < 4; i++ {
		select {
		case name := <-resultc:
			require.Condition(t,
				func() (success bool) {
					success = i<3
					return success
				},
				"should return only 3 names!",
			)
			names[i] = name
		case err := <-errc:
			assert.Equal(t, 3, i)
			assert.Equal(t, err, io.EOF)
			break loop
		}
	}
	assert.Equal(t, namesInit, names)
}
