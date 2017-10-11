package console


import (
	"context"
	"fmt"
)

/*
This is the interface that console module implement.
 */
type Service interface {
	PrintEvent(ctx context.Context, event string)
}

/*
 */
func NewBasicService() Service {
	return &basicService{}
}

type basicService struct {
}

func (u *basicService)PrintEvent(ctx context.Context, event string){
	fmt.Println(event)
}