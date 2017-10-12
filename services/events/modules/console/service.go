package console


import (
	"context"
	"fmt"
)

/*
This is the interface that console module implement.
 */
type Service interface {
	Print(ctx context.Context, args ...string)
}

/*
 */
func NewBasicService() Service {
	return &basicService{}
}

type basicService struct {
}

func (u *basicService)Print(ctx context.Context, args ...string){
	fmt.Println(args)
}


