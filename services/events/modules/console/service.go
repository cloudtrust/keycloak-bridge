package console


import (
	"fmt"
)

/*
This is the interface that console module implement.
 */
type Service interface {
	Print(map[string]string) error
}

/*
 */
func NewBasicService() Service {
	return &basicService{}
}

type basicService struct {
}

func (u *basicService)Print(m map[string]string) error{
	for k, v := range m{
		fmt.Println(k, "=", v)
	}
	return nil
}


/*

 */
type KeycloakStatisticsProcessor interface{
	Stats(map[string]string) (interface{}, error)
}

func NewKeycloakStatisticsProcessor() KeycloakStatisticsProcessor {
	return &keycloakStatisticsProcessor{}
}

type keycloakStatisticsProcessor struct {}

func (k *keycloakStatisticsProcessor) Stats(map[string]string) (interface{}, error){
	fmt.Println("Stats")
	return nil, nil
}
