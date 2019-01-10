package elasticsearch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

// Client for interaction with Elasticsearch
type Client struct {
	c    *http.Client
	addr string
}

// NewClient returns a new Elasticsearch client.
func NewClient(addr string, httpClient *http.Client) *Client {
	return &Client{
		c:    httpClient,
		addr: addr,
	}
}

// IndexData index the document 'data' under a type  in
func (c *Client) IndexData(esIndex, esType, id, timestamp string, data interface{}) error {

	var d, err = json.Marshal(data)
	if err != nil {
		return errors.Wrap(err, "could not marhsal data")
	}

	var req *http.Request
	{
		var err error
		req, err = http.NewRequest("PUT", fmt.Sprintf("http://%s/%s/%s/%s?timestamp=%s", c.addr, esIndex, esType, id, timestamp), bytes.NewReader(d))
		if err != nil {
			return errors.Wrap(err, "could not create http request")
		}
		req.Header.Set("Content-type", "application/json")
	}

	var res *http.Response
	{
		var err error
		res, err = http.DefaultClient.Do(req)
		if res != nil {
			defer res.Body.Close()
		}
		if err != nil {
			return errors.Wrap(err, "could not execute http request")
		}
	}
	return nil
}
