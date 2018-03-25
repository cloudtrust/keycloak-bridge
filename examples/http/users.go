package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/cloudtrust/keycloak-bridge/api/user/fb"
	"github.com/go-kit/kit/log"
	"github.com/google/flatbuffers/go"
	opentracing "github.com/opentracing/opentracing-go"
	otag "github.com/opentracing/opentracing-go/ext"
	"github.com/spf13/pflag"
	jaeger_client "github.com/uber/jaeger-client-go/config"
)

var (
	host = pflag.String("host", "127.0.0.1", "keycloak bridge host")
	port = pflag.String("port", "8888", "keycloak bridge port")
)

func main() {
	// Configuration flags.
	pflag.Parse()

	// Logger.
	var logger = log.NewLogfmtLogger(os.Stdout)
	{
		logger = log.With(logger, "time", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
		defer logger.Log("msg", "Goodbye")
	}
	logger = log.With(logger, "transport", "http")

	// Jaeger tracer config.
	var jaegerConfig = jaeger_client.Configuration{
		Sampler: &jaeger_client.SamplerConfig{
			Type:              "const",
			Param:             1,
			SamplingServerURL: "http://127.0.0.1:5775",
		},
		Reporter: &jaeger_client.ReporterConfig{
			LogSpans:            false,
			BufferFlushInterval: 1000 * time.Millisecond,
		},
	}

	// Jaeger client.
	var tracer opentracing.Tracer
	{
		var logger = log.With(logger, "component", "jaeger")
		var closer io.Closer
		var err error

		tracer, closer, err = jaegerConfig.New("keycloak-user-client")
		if err != nil {
			logger.Log("error", err)
			return
		}
		defer closer.Close()
	}

	// GetUsers.
	var b = flatbuffers.NewBuilder(0)
	var brealm = b.CreateString("master")
	fb.GetUsersRequestStart(b)
	fb.GetUsersRequestAddRealm(b, brealm)
	b.Finish(fb.GetUsersRequestEnd(b))

	var span = tracer.StartSpan("http_client_getusers")
	otag.HTTPMethod.Set(span, "http-client")
	defer span.Finish()

	// http NextID
	var httpGetUsersRep *http.Response
	{
		var err error
		var req *http.Request
		var url = fmt.Sprintf("http://%s:%s/getusers", *host, *port)

		req, err = http.NewRequest("POST", url, bytes.NewReader(b.FinishedBytes()))
		if err != nil {
			logger.Log("error", err)
			return
		}

		var carrier = opentracing.HTTPHeadersCarrier(req.Header)
		tracer.Inject(span.Context(), opentracing.HTTPHeaders, carrier)

		req.Header.Set("Content-Type", "application/octet-stream")

		//req.Header.Set("X-Correlation-ID", "1")
		httpGetUsersRep, err = http.DefaultClient.Do(req)

		if err != nil {
			logger.Log("error", err)
			return
		}
		defer httpGetUsersRep.Body.Close()

		// Read flatbuffer reply.
		var data []byte
		data, err = ioutil.ReadAll(httpGetUsersRep.Body)
		if err != nil {
			logger.Log("error", err)
			return
		}

		if httpGetUsersRep.StatusCode != 200 {
			logger.Log("error", string(data))
		} else {
			var reply = fb.GetRootAsGetUsersReply(data, 0)
			for i := 0; i < reply.NamesLength(); i++ {
				logger.Log("name", string(reply.Names(i)))
			}
		}
	}
}
