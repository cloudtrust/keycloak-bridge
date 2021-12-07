package business

import (
	"testing"
	"time"

	"github.com/cloudtrust/common-service/v2/log"
	"github.com/stretchr/testify/assert"
)

const (
	psyRegValidResponse = `
	{"personenCount":1,"maxResultExceeded":false,"personen":[{"personId":508,"vorname":"Marc","name":"El Bichon","berufsbezeichnungId":54002,"sprachIds":[13001],"plzOrtCollection":[{"plz":"1207","ort":"Genève"}],"kantonId":11025,"bewilligungsstatusId":53001,"isMeldungNeunzigTageDienstleisterCurrentYear":false}]}
	`
	psyRegNotFoundResponse = `{"personenCount":0}`
	psyRegActiveNumbers    = `WyI3NjAxMDA3NTY0OTI3IiwiNzYwMTAwNzU2NDkyNyIsIjc2MDEwMDc0OTgyMjIiLCI3NjAxMDAzOTEzNTgzIiwiNzYwMTAwNzU2NjkzOCIsIjc2MDEwMDM5NjU0NDUiXQ==`
)

func TestPsyRegSimulatedLookup(t *testing.T) {
	t.Run("Invalid URL", func(t *testing.T) {
		var _, err = NewPsyRegLookup("\n", time.Millisecond, nil)
		assert.NotNil(t, err)
	})
	t.Run("Request fails", func(t *testing.T) {
		var rdl, err = NewPsyRegLookup("http://localhost/", time.Millisecond*500, log.NewNopLogger())
		assert.Nil(t, err)

		var details = rdl.Lookup("123456789")
		assert.NotNil(t, details.Error)
	})
	t.Run("Valid result", func(t *testing.T) {
		inWebServer("application/json", map[string]string{"/api/personen/search": psyRegValidResponse}, func(URL string) {
			var rdl, err = NewPsyRegLookup(URL, time.Second*10, log.NewNopLogger())
			assert.Nil(t, err)

			var details = rdl.Lookup("123456789")
			assert.Nil(t, details.Error)
			assert.Equal(t, "Marc", *details.Persons[0].FirstName)
			assert.Equal(t, "El Bichon", *details.Persons[0].LastName)
			assert.Equal(t, "1207", *details.Persons[0].ZipCode)
			assert.Equal(t, "Genève", *details.Persons[0].City)
		})
	})
	t.Run("Not found result", func(t *testing.T) {
		inWebServer("application/json", map[string]string{"/api/personen/search": psyRegNotFoundResponse}, func(URL string) {
			var rdl, err = NewPsyRegLookup(URL, time.Second*10, log.NewNopLogger())
			assert.Nil(t, err)

			var details = rdl.Lookup("123456789")
			assert.Equal(t, ErrGLNNotFound, details.Error)
		})
	})
}

func TestPsyRegRealParameters(t *testing.T) {
	t.Skip()

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
