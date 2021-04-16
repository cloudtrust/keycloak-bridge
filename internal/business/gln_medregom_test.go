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
	medRegOmResponse = `
	{"emptyrowdata":{"Beruf":null},"rows":[{"Beruf":"Médecin ","FirstName":"Marc","Id":30658,"LastName":"El Bichon","Ort":["Genève","Lausanne","Zurich"],"Plz":["1207","1004","1174"],"Score":1,"Strasse":["Avenue des Acacias 43","Route de nulle part 4","Die Strasse 6"],"Weiterbildungen":"Pratique du laboratoire au cabinet musical"}],"settings":{"currentpage":1,"totalrecords":1},"additionalInfo":{"Diplome":{"1":1,"999999":1},"Spezialisierungen":{"1051":1}}}
	`
)

type medRegOmWebServer struct {
}

func (*medRegOmWebServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	var result = medRegOmResponse
	writer.Header().Add("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	writer.Write([]byte(result))
}

func TestMedRegOmLookup(t *testing.T) {
	var handler medRegOmWebServer
	r := mux.NewRouter()
	r.Handle("/FR/Suche/GetSearchData", &handler)

	ts := httptest.NewServer(r)
	defer ts.Close()

	var rdl, err = NewMedRegOmLookup(ts.URL, time.Second*10, log.NewNopLogger())

	assert.Nil(t, err)

	var details = rdl.Lookup("123456789")
	assert.Nil(t, details.Error)
	assert.Len(t, details.Persons, 1)
	assert.Equal(t, "Marc", *details.Persons[0].FirstName)
	assert.Equal(t, "El Bichon", *details.Persons[0].LastName)
	assert.Equal(t, "1207", *details.Persons[0].ZipCode)
	assert.Equal(t, "Genève", *details.Persons[0].City)
}

func TestMedRegOmRealParameters(t *testing.T) {
	var rdl, err = NewMedRegOmLookup("https://www.medregom.admin.ch", time.Second*10, log.NewNopLogger())
	assert.Nil(t, err)

	t.Run("True number", func(t *testing.T) {
		var details = rdl.Lookup("7601000001726")
		assert.Nil(t, details.Error)
		assert.Equal(t, "1006", *details.Persons[0].ZipCode)
		assert.Equal(t, "Lausanne", *details.Persons[0].City)
	})
	t.Run("Wrong number", func(t *testing.T) {
		var details = rdl.Lookup("1601000001700")
		assert.Equal(t, ErrGLNNotFound, details.Error)
	})
}
