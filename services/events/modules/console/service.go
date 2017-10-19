package console


import (
	"github.com/go-kit/kit/log"
)

/*
This is the interface that console module implement.
 */
type Service interface {
	Print(map[string]string) error
}

/*
 */
func NewBasicService(logger *log.Logger) Service {
	return &basicService{
		logger: logger,
	}
}

type basicService struct {
	logger *log.Logger
}

func (u *basicService)Print(m map[string]string) error{
	for k, v := range m{
		(*u.logger).Log(k, v)
	}
	return nil
}

