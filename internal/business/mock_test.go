package business

import (
	"net/http"
	"net/http/httptest"

	"github.com/gorilla/mux"
)

type webServer struct {
	contentType string
	response    string
}

func (ws *webServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Add("Content-Type", ws.contentType)
	writer.WriteHeader(http.StatusOK)
	writer.Write([]byte(ws.response))
}

func inWebServer(contentType string, responses map[string]string, callback func(string)) {
	r := mux.NewRouter()
	for path, response := range responses {
		var handler = webServer{contentType: contentType, response: response}
		r.Handle(path, &handler)
	}

	ts := httptest.NewServer(r)
	defer ts.Close()

	callback(ts.URL)
}
