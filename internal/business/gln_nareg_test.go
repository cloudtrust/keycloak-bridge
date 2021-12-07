package business

import (
	"testing"
	"time"

	"github.com/cloudtrust/common-service/v2/log"
	"github.com/stretchr/testify/assert"
)

const (
	naRegValidResponse = `
	{"Data":[{"Addresses":[{"Id":26913,"Street":"Route des acacias  11","Zip":"1027","Place":"Genève Adm cant GE"}],"PersonLastName":"El Bichon","PersonIsAnonymized":false,"PersonId":130036,"DuplicatePersonId":null,"DuplicateMode":false,"PersonGlnNumber":"000000000","PersonFirstName":"Marc","LicenceId":24655,"CodeTranslationLicenceCantonLabel":"Vaud","CodeTranslationDiplomaProfessionLabel":"Soins infirmiers","CodePersonSexId":1002,"CodeLicenceStatusId":null,"CodeLicenceProfessionId":null,"CodeLicenceLicenceTypeId":null,"CodeLicenceCantonId":7023,"CodeDiplomaProfessionId":5015,"AddressZip":null,"AddressStreet":null,"AddressPlace":null,"AddressId":null}],"Total":1,"AggregateResults":null,"Errors":null}
	`
	naRegNotFoundResponse = `
	{"Data":[],"Total":0,"AggregateResults":null,"Errors":null}
	`
	naRegActiveNumbers = `WyI3NjAxMDA3NTgyMDM3IiwiNzYwMTAwNzk3MDgwMyIsIjc2MDEwMDM0NzUwNTAiLCI3NjAxMDAxMjAyMzM3IiwiNzYwMTAwMzYxNjY2OCIsIjc2MDEwMDM0NzY1MTQiLCI3NjAxMDAzMjYzMjA2Il0=`
)

func TestNaRegLookup(t *testing.T) {
	t.Run("Invalid URL", func(t *testing.T) {
		var _, err = NewNaRegLookup("\n", time.Millisecond, nil)
		assert.NotNil(t, err)
	})
	t.Run("Request fails", func(t *testing.T) {
		var rdl, err = NewNaRegLookup("http://localhost/", time.Millisecond*500, log.NewNopLogger())
		assert.Nil(t, err)

		var details = rdl.Lookup("123456789")
		assert.NotNil(t, details.Error)
	})
	t.Run("Valid response", func(t *testing.T) {
		inWebServer("application/json", map[string]string{"/Search/Read": naRegValidResponse}, func(URL string) {
			var rdl, err = NewNaRegLookup(URL, time.Second*10, log.NewNopLogger())

			assert.Nil(t, err)

			var details = rdl.Lookup("123456789")
			assert.Nil(t, details.Error)
			assert.Len(t, details.Persons, 1)
			assert.Equal(t, "Marc", *details.Persons[0].FirstName)
			assert.Equal(t, "El Bichon", *details.Persons[0].LastName)
			assert.Equal(t, "1027", *details.Persons[0].ZipCode)
			assert.Equal(t, "Genève Adm cant GE", *details.Persons[0].City)
		})
	})
	t.Run("Not found response", func(t *testing.T) {
		inWebServer("application/json", map[string]string{"/Search/Read": naRegNotFoundResponse}, func(URL string) {
			var rdl, err = NewNaRegLookup(URL, time.Second*10, log.NewNopLogger())
			assert.Nil(t, err)

			var details = rdl.Lookup("123456789")
			assert.Equal(t, ErrGLNNotFound, details.Error)
		})
	})
}

func TestNaRegRealParameters(t *testing.T) {
	t.Skip()

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
