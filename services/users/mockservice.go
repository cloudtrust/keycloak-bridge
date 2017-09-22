package users

import (
	"io"
	"context"
)

type mockService struct {
	names []string
}

func NewMockService(names []string) Service {
	return &mockService{names:names}
}

func (m *mockService)GetUsers(ctx context.Context, realm string) (<-chan string, <-chan error) {
	var resultc = make(chan string)
	var errc = make(chan error)
	go func() {
		for _, n := range m.names {
			resultc<-n
		}
		errc <- io.EOF
	}()
	return resultc, errc
}