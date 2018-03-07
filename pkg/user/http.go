package user

import (
	"context"
	"io/ioutil"
	"net/http"

	"github.com/cloudtrust/keycloak-bridge/pkg/user/flatbuffer/fb"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
	"github.com/google/flatbuffers/go"
	"github.com/pkg/errors"
)

// MakeHTTPGetUsersHandler makes a HTTP handler for the GetUsers endpoint.
func MakeHTTPGetUsersHandler(e endpoint.Endpoint) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeHTTPRequest,
		encodeHTTPReply,
		http_transport.ServerErrorEncoder(httpErrorHandler),
		http_transport.ServerBefore(fetchHTTPCorrelationID),
	)
}

// fetchHTTPCorrelationID reads the correlation ID from the http header "X-Correlation-ID".
// If the ID is not zero, we put it in the context.
func fetchHTTPCorrelationID(ctx context.Context, req *http.Request) context.Context {
	var correlationID = req.Header.Get("X-Correlation-ID")
	if correlationID != "" {
		ctx = context.WithValue(ctx, CorrelationIDKey, correlationID)
	}
	return ctx
}

// decodeHTTPRequest decodes the flatbuffer getUsers request.
func decodeHTTPRequest(_ context.Context, req *http.Request) (interface{}, error) {
	var data, err = ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode HTTP request")
	}

	return fb.GetRootAsGetUsersRequest(data, 0), nil
}

// encodeHTTPReply encodes the flatbuffer flaki reply.
func encodeHTTPReply(_ context.Context, w http.ResponseWriter, rep interface{}) error {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)

	var reply = rep.(*fb.GetUsersResponse)

	var usersNames []string
	for i := 0; i < reply.NamesLength(); i++ {
		usersNames = append(usersNames, string(reply.Names(i)))
	}

	var b = flatbuffers.NewBuilder(0)
	var userOffsets = []flatbuffers.UOffsetT{}
	for _, u := range usersNames {
		userOffsets = append(userOffsets, b.CreateString(u))
	}

	fb.GetUsersResponseStartNamesVector(b, len(usersNames))
	for _, u := range userOffsets {
		b.PrependUOffsetT(u)
	}
	var names = b.EndVector(len(usersNames))
	fb.GetUsersResponseStart(b)
	fb.GetUsersResponseAddNames(b, names)
	b.Finish(fb.GetUsersResponseEnd(b))

	w.Write(b.FinishedBytes())
	return nil
}

// httpErrorHandler encodes the flatbuffer flaki reply when there is an error.
func httpErrorHandler(ctx context.Context, err error, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(err.Error()))
}
