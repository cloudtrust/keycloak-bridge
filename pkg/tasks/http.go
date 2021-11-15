package tasks

import (
	commonhttp "github.com/cloudtrust/common-service/http"
	"github.com/cloudtrust/common-service/log"

	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

// MakeTasksHandler make an HTTP handler for a Tasks endpoint.
func MakeTasksHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	return http_transport.NewServer(e,
		commonhttp.BasicDecodeRequest,
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}
