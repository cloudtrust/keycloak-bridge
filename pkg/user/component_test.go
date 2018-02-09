package user

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComponent(t *testing.T) {
	var users = []string{"john", "jane", "doe"}
	var mockModule = &mockModule{
		called: false,
		fail:   false,
		users:  users,
	}

	var c = NewComponent(mockModule)
	var names, err = c.GetUsers(context.Background(), "realm")
	assert.Nil(t, err)
	assert.Equal(t, users, names)
}

// Mock Component.
type mockComponent struct {
	called bool
	fail   bool
	users  []string
}

func (c *mockComponent) GetUsers(ctx context.Context, realm string) ([]string, error) {
	if c.fail {
		return nil, fmt.Errorf("fail")
	}
	return c.users, nil
}
