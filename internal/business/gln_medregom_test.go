package business

import (
	"testing"
	"time"

	"github.com/cloudtrust/common-service/log"
	"github.com/stretchr/testify/assert"
)

const (
	medRegValidResponse = `
	{"emptyrowdata":{"Beruf":null},"rows":[{"Beruf":"Médecin ","FirstName":"Marc","Id":30658,"LastName":"El Bichon","Ort":["Genève","Lausanne","Zurich"],"Plz":["1207","1004","1174"],"Score":1,"Strasse":["Avenue des Acacias 43","Route de nulle part 4","Die Strasse 6"],"Weiterbildungen":"Pratique du laboratoire au cabinet musical"}],"settings":{"currentpage":1,"totalrecords":1},"additionalInfo":{"Diplome":{"1":1,"999999":1},"Spezialisierungen":{"1051":1}}}
	`
	medRegNotFoundResponse = `
	{"emptyrowdata":{"Beruf":null},"rows":[],"settings":{"currentpage":1,"totalrecords":0}}
	`
)

func TestMedRegOmLookup(t *testing.T) {
	t.Run("Invalid URL", func(t *testing.T) {
		var _, err = NewMedRegOmLookup("\n", time.Millisecond, nil)
		assert.NotNil(t, err)
	})
	t.Run("Request fails", func(t *testing.T) {
		var rdl, err = NewMedRegOmLookup("http://localhost/", time.Millisecond*500, log.NewNopLogger())
		assert.Nil(t, err)

		var details = rdl.Lookup("123456789")
		assert.NotNil(t, details.Error)
	})
	t.Run("Valid response", func(t *testing.T) {
		inWebServer("application/json", map[string]string{"/FR/Suche/GetSearchData": medRegValidResponse}, func(URL string) {
			var rdl, err = NewMedRegOmLookup(URL, time.Second*10, log.NewNopLogger())

			assert.Nil(t, err)

			var details = rdl.Lookup("123456789")
			assert.Nil(t, details.Error)
			assert.Len(t, details.Persons, 1)
			assert.Equal(t, "Marc", *details.Persons[0].FirstName)
			assert.Equal(t, "El Bichon", *details.Persons[0].LastName)
			assert.Equal(t, "1207", *details.Persons[0].ZipCode)
			assert.Equal(t, "Genève", *details.Persons[0].City)
		})
	})
	t.Run("Empty response", func(t *testing.T) {
		inWebServer("application/json", map[string]string{"/FR/Suche/GetSearchData": medRegNotFoundResponse}, func(URL string) {
			var rdl, err = NewMedRegOmLookup(URL, time.Second*10, log.NewNopLogger())
			assert.Nil(t, err)

			var details = rdl.Lookup("123456789")
			assert.Equal(t, ErrGLNNotFound, details.Error)
		})
	})
}

func TestMedRegOmRealParameters(t *testing.T) {
	t.Skip()

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
