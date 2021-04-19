package business

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudtrust/common-service/log"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

const (
	psyRegResponse = `
	{"personenCount":1,"maxResultExceeded":false,"personen":[{"personId":508,"vorname":"Marc","name":"El Bichon","berufsbezeichnungId":54002,"sprachIds":[13001],"plzOrtCollection":[{"plz":"1207","ort":"Genève"}],"kantonId":11025,"bewilligungsstatusId":53001,"isMeldungNeunzigTageDienstleisterCurrentYear":false}]}
	`
	psyRegActiveNumbers = `WyI3NjAxMDA3NTY0OTI3IiwiNzYwMTAwNzU2NDkyNyIsIjc2MDEwMDc0OTgyMjIiLCI3NjAxMDAzOTEzNTgzIiwiNzYwMTAwNzU2NjkzOCIsIjc2MDEwMDM5NjU0NDUiXQ==`
)

type psyRegWebServer struct {
}

func (*psyRegWebServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	var result = psyRegResponse
	writer.Header().Add("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	writer.Write([]byte(result))
}

func TestPsyRegLookup(t *testing.T) {
	var handler psyRegWebServer
	r := mux.NewRouter()
	r.Handle("/api/personen/search", &handler)

	ts := httptest.NewServer(r)
	defer ts.Close()

	var rdl, err = NewPsyRegLookup(ts.URL, time.Second*10, log.NewNopLogger())

	assert.Nil(t, err)

	var details = rdl.Lookup("123456789")
	assert.Nil(t, details.Error)
	assert.Equal(t, "Marc", *details.Persons[0].FirstName)
	assert.Equal(t, "El Bichon", *details.Persons[0].LastName)
	assert.Equal(t, "1207", *details.Persons[0].ZipCode)
	assert.Equal(t, "Genève", *details.Persons[0].City)
}

func TestPsyRegRealParameters(t *testing.T) {
	var rdl, err = NewPsyRegLookup("https://ws.psyreg.bag.admin.ch", time.Second*10, log.NewNopLogger())
	assert.Nil(t, err)

	var gln = choose(psyRegActiveNumbers)
	t.Run("Active number "+gln, func(t *testing.T) {
		var details = rdl.Lookup(gln)
		assert.Nil(t, details.Error)
		assert.Len(t, details.Persons, 1)
		assert.NotNil(t, *details.Persons[0].FirstName)
		assert.NotNil(t, *details.Persons[0].LastName)
		assert.NotNil(t, *details.Persons[0].ZipCode)
		assert.NotNil(t, *details.Persons[0].City)
	})
	gln = "1601003913000"
	t.Run("Wrong number "+gln, func(t *testing.T) {
		var details = rdl.Lookup(gln)
		assert.Equal(t, ErrGLNNotFound, details.Error)
	})
}
