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
	naRegResponse = `
	{"Data":[{"Addresses":[{"Id":26913,"Street":"Route des acacias  11","Zip":"1027","Place":"Genève Adm cant GE"}],"PersonLastName":"El Bichon","PersonIsAnonymized":false,"PersonId":130036,"DuplicatePersonId":null,"DuplicateMode":false,"PersonGlnNumber":"000000000","PersonFirstName":"Marc","LicenceId":24655,"CodeTranslationLicenceCantonLabel":"Vaud","CodeTranslationDiplomaProfessionLabel":"Soins infirmiers","CodePersonSexId":1002,"CodeLicenceStatusId":null,"CodeLicenceProfessionId":null,"CodeLicenceLicenceTypeId":null,"CodeLicenceCantonId":7023,"CodeDiplomaProfessionId":5015,"AddressZip":null,"AddressStreet":null,"AddressPlace":null,"AddressId":null}],"Total":1,"AggregateResults":null,"Errors":null}
	`
	naRegActiveNumbers = `WyI3NjAxMDA3NTgyMDM3IiwiNzYwMTAwNzk3MDgwMyIsIjc2MDEwMDM0NzUwNTAiLCI3NjAxMDAxMjAyMzM3IiwiNzYwMTAwMzYxNjY2OCIsIjc2MDEwMDM0NzY1MTQiLCI3NjAxMDAzMjYzMjA2Il0=`
)

type naRegWebServer struct {
}

func (*naRegWebServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	var result = naRegResponse
	writer.Header().Add("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	writer.Write([]byte(result))
}

func TestNaRegLookup(t *testing.T) {
	var handler naRegWebServer
	r := mux.NewRouter()
	r.Handle("/Search/DoSearch", &handler)
	r.Handle("/Search/Read", &handler)

	ts := httptest.NewServer(r)
	defer ts.Close()

	var rdl, err = NewNaRegLookup(ts.URL, time.Second*10, log.NewNopLogger())

	assert.Nil(t, err)

	var details = rdl.Lookup("123456789")
	assert.Nil(t, details.Error)
	assert.Len(t, details.Persons, 1)
	assert.Equal(t, "Marc", *details.Persons[0].FirstName)
	assert.Equal(t, "El Bichon", *details.Persons[0].LastName)
	assert.Equal(t, "1027", *details.Persons[0].ZipCode)
	assert.Equal(t, "Genève Adm cant GE", *details.Persons[0].City)
}

func TestNaRegRealParameters(t *testing.T) {
	var rdl, err = NewNaRegLookup("https://www.nareg.ch", time.Second*10, log.NewNopLogger())
	assert.Nil(t, err)

	var gln = choose(naRegActiveNumbers)
	t.Run("Active number "+gln, func(t *testing.T) {
		var details = rdl.Lookup(gln)
		assert.Nil(t, details.Error)
		assert.True(t, len(details.Persons) > 0)
		assert.NotNil(t, *details.Persons[0].FirstName)
		assert.NotNil(t, *details.Persons[0].LastName)
	})
	gln = "1601007043500"
	t.Run("Wrong number "+gln, func(t *testing.T) {
		var details = rdl.Lookup(gln)
		assert.Equal(t, ErrGLNNotFound, details.Error)
	})
}
