package user

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetUsers(t *testing.T) {
	var names = []string{"john", "jane", "doe"}
	var mockComponent = &mockComponent{
		called: false,
		fail:   false,
		users:  names,
	}

	var getUsersEndpoint = NewEndpoints()
	getUsersEndpoint.MakeGetUsersEndpoint(mockComponent)

	var namess, err = getUsersEndpoint.GetUsers(context.Background(), "master")
	assert.Nil(t, err)
	assert.Equal(t, names, namess)
}

type mockService struct {
	names []string
}

func (m *mockService) GetUsers(ctx context.Context, realm string) (<-chan string, <-chan error) {
	var resultc = make(chan string)
	var errc = make(chan error)
	go func() {
		for _, n := range m.names {
			resultc <- n
		}
		errc <- io.EOF
	}()
	return resultc, errc
}
