package idgenerator

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"
)

// New returns an ID generator which generate a unique id.
func New(componentName, componentID string) IDGenerator {
	return &generator{
		componentID: componentID,
		componentName: componentName,
	}
}

type IDGenerator interface{
	NextID() string
}

type generator struct {
	componentID string
	componentName string
}

// Generate a unique id with following format: <componentName>-<componentID>-<time>-<random number>
func (g *generator) NextID() string {
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var time = strconv.FormatInt(time.Now().Unix(), 10)
	return fmt.Sprintf("%s-%s-%s-%s", g.componentName, g.componentID, time, id)
}
