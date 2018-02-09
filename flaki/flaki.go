package flaki

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/cloudtrust/keycloak-bridge/flaki/flatbuffer/fb"
	flatbuffers "github.com/google/flatbuffers/go"
	opentracing "github.com/opentracing/opentracing-go"
	otag "github.com/opentracing/opentracing-go/ext"
)

// Client is the Flaki client.
type Client struct {
	url    string
	tracer opentracing.Tracer
}

// NewClient returns a flaki client.
func NewClient(url string, tracer opentracing.Tracer) *Client {
	return &Client{
		url:    url,
		tracer: tracer,
	}
}

// GetCorrelationID returns a unique correlation ID.
func (c *Client) GetCorrelationID(ctx context.Context) (string, error) {
	var b = flatbuffers.NewBuilder(0)
	fb.EmptyRequestStart(b)
	b.Finish(fb.EmptyRequestEnd(b))

	var span = c.tracer.StartSpan("http")
	otag.HTTPMethod.Set(span, "keycloak-bridge")
	defer span.Finish()

	var url = fmt.Sprintf("http://%s/nextvalidid", c.url)

	var req *http.Request
	{
		var err error
		req, err = http.NewRequest("POST", url, bytes.NewReader(b.FinishedBytes()))
		if err != nil {
			return "", err
		}

		var carrier = opentracing.HTTPHeadersCarrier(req.Header)
		c.tracer.Inject(span.Context(), opentracing.HTTPHeaders, carrier)

		req.Header.Set("Content-Type", "application/octet-stream")
	}

	var resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	// Read flatbuffer reply.
	var data []byte
	{
		var err error
		data, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
	}

	var reply = fb.GetRootAsFlakiReply(data, 0)

	return string(reply.Id()), nil
}

func (c *Client) Ping() error {
	var url = fmt.Sprintf("http://%s", c.url)

	var resp, err = http.Get(url)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status code is not 200 OK: %v", resp.Status)
	}
	return nil
}
