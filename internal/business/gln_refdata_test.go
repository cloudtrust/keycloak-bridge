package business

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"testing"
	"time"

	"github.com/cloudtrust/common-service/log"
	"github.com/stretchr/testify/assert"
)

const (
	refDataValidResponse = `
	<?xml version="1.0" encoding="utf-8"?>
	<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
		<soap:Body>
			<PARTNER CREATION_DATETIME="2021-04-19T14:06:58.6070882+02:00" xmlns="http://refdatabase.refdata.ch/">
				<ITEM DT="2016-01-06T00:00:00" xmlns="http://refdatabase.refdata.ch/Partner_out">
					<PTYPE>NAT</PTYPE> <GLN>111111111</GLN> <STATUS>A</STATUS>
					<STDATE>2008-11-07T00:00:00</STDATE> <LANG>FR</LANG>
					<DESCR1>El Bichon</DESCR1>
					<DESCR2>Marc</DESCR2>
					<ROLE>
						<TYPE>Pharmst</TYPE> <ZIP>1207</ZIP> <CITY>Genève</CITY> <CTN>GE</CTN> <CNTRY>CH</CNTRY>
					</ROLE>
				</ITEM>
				<ITEM DT="2016-01-06T00:00:00" xmlns="http://refdatabase.refdata.ch/Partner_out">
					<PTYPE>NAT</PTYPE> <GLN>222222222</GLN> <STATUS>I</STATUS>
					<STDATE>2008-11-07T00:00:00</STDATE> <LANG>FR</LANG>
					<DESCR1>Ombrage</DESCR1>
					<DESCR2>Sophie</DESCR2>
					<ROLE>
						<TYPE>Pharmst</TYPE> <ZIP>1001</ZIP> <CITY>Lausanne</CITY> <CTN>VD</CTN> <CNTRY>CH</CNTRY>
					</ROLE>
				</ITEM>
				<RESULT xmlns="http://refdatabase.refdata.ch/Partner_out">
					<OK_ERROR>OK</OK_ERROR>
					<NBR_RECORD>1</NBR_RECORD>
				</RESULT>
			</PARTNER>
		</soap:Body>
	</soap:Envelope>
	`
	refDataInvalidFormatResponse = `
	<?xml version="1.0" encoding="utf-8"?>
	<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
		<soap:Body>
			<PARTNER CREATION_DATETIME="2021-04-19T14:06:58.6070882+02:00" xmlns="http://refdatabase.refdata.ch/">
				<RESULT xmlns="http://refdatabase.refdata.ch/Partner_out">
					<OK_ERROR>ERROR</OK_ERROR>
					<NBR_RECORD>0</NBR_RECORD>
				</RESULT>
			</PARTNER>
		</soap:Body>
	</soap:Envelope>
	`
	refDataNotFoundResponse = `
	<?xml version="1.0" encoding="utf-8"?>
	<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
		<soap:Body>
			<PARTNER CREATION_DATETIME="2021-04-19T14:06:58.6070882+02:00" xmlns="http://refdatabase.refdata.ch/">
				<RESULT xmlns="http://refdatabase.refdata.ch/Partner_out">
					<OK_ERROR>OK</OK_ERROR>
					<NBR_RECORD>0</NBR_RECORD>
				</RESULT>
			</PARTNER>
		</soap:Body>
	</soap:Envelope>
	`
	activeNumbers   = `WyI3NjAxMDAyNjczOTUyIiwgIjc2MDEwMDMxNDMxMjYiLCAiNzYwMTAwMjYzNjMyMiIsICI3NjAxMDAwNjY2Nzk2IiwgIjc2MDEwMDAwMTkyODgiLCAiNzYwMTAwMzYwMzg5NyIsICI3NjAxMDAzMjk0MTMyIl0=`
	inactiveNumbers = `WyI3NjAxMDAwNDYwNzkwIiwiNzYwMTAwMDMyMzk1OCIsIjc2MDEwMDA3ODUwODQiLCI3NjAxMDAwMjgxNTU1IiwiNzYwMTAwMDMyMzkzNCIsIjc2MDEwMDAyMzU2NDAiLCI3NjAxMDAwMzk2MjExIiwiNzYwMTAwMDI3ODI5NiJd`
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

func choose(input string) string {
	var bytes, _ = base64.StdEncoding.DecodeString(input)
	var numbers []string
	_ = json.Unmarshal(bytes, &numbers)
	var idx = rand.Int() % len(numbers)
	return numbers[idx]
}

func TestSimulatedLookup(t *testing.T) {
	t.Run("Invalid URL", func(t *testing.T) {
		var _, err = NewRefDataLookup("\n", time.Second*10, log.NewNopLogger())
		assert.NotNil(t, err)
	})
	t.Run("Can't connect", func(t *testing.T) {
		var rdl, err = NewRefDataLookup("http://localhost:12345/", time.Millisecond, log.NewNopLogger())
		assert.Nil(t, err)

		var details = rdl.Lookup("123456789")
		assert.NotNil(t, details.Error)
		assert.NotEqual(t, ErrGLNNotFound, details.Error)
		assert.NotEqual(t, ErrGLNDoesNotMatch, details.Error)
	})
	t.Run("Unparsable response", func(t *testing.T) {
		inWebServer("text/xml; charset=utf-8", map[string]string{"/Service/Partner.asmx": `not-xml-content`}, func(URL string) {
			var rdl, err = NewRefDataLookup(URL+"/Service/Partner.asmx", time.Second*10, log.NewNopLogger())
			assert.Nil(t, err)

			var details = rdl.Lookup("123456789")
			assert.Equal(t, ErrGLNCantParse, details.Error)
		})
	})
	t.Run("Valid response with two results", func(t *testing.T) {
		inWebServer("text/xml; charset=utf-8", map[string]string{"/Service/Partner.asmx": refDataValidResponse}, func(URL string) {
			var rdl, err = NewRefDataLookup(URL+"/Service/Partner.asmx", time.Second*10, log.NewNopLogger())
			assert.Nil(t, err)

			var gln = choose(activeNumbers)
			var details = rdl.Lookup(gln)
			assert.Nil(t, details.Error)
			assert.Len(t, details.Persons, 2)

			assert.Equal(t, "111111111", *details.Persons[0].Number)
			assert.True(t, *details.Persons[0].Active)
			assert.Equal(t, "Marc", *details.Persons[0].FirstName)
			assert.Equal(t, "El Bichon", *details.Persons[0].LastName)
			assert.Equal(t, "1207", *details.Persons[0].ZipCode)
			assert.Equal(t, "Genève", *details.Persons[0].City)

			assert.Equal(t, "222222222", *details.Persons[1].Number)
			assert.False(t, *details.Persons[1].Active)
			assert.Equal(t, "Sophie", *details.Persons[1].FirstName)
			assert.Equal(t, "Ombrage", *details.Persons[1].LastName)
			assert.Equal(t, "1001", *details.Persons[1].ZipCode)
			assert.Equal(t, "Lausanne", *details.Persons[1].City)
		})
	})
	t.Run("Requested GLN has invalid format", func(t *testing.T) {
		inWebServer("text/xml; charset=utf-8", map[string]string{"/Service/Partner.asmx": refDataInvalidFormatResponse}, func(URL string) {
			var rdl, err = NewRefDataLookup(URL+"/Service/Partner.asmx", time.Second*10, log.NewNopLogger())
			assert.Nil(t, err)

			var details = rdl.Lookup("123456789")
			assert.Equal(t, ErrGLNNotFound, details.Error)
		})
	})
	t.Run("Requested GLN is not found", func(t *testing.T) {
		inWebServer("text/xml; charset=utf-8", map[string]string{"/Service/Partner.asmx": refDataNotFoundResponse}, func(URL string) {
			var rdl, err = NewRefDataLookup(URL+"/Service/Partner.asmx", time.Second*10, log.NewNopLogger())
			assert.Nil(t, err)

			var details = rdl.Lookup("123456789")
			assert.Equal(t, ErrGLNNotFound, details.Error)
		})
	})
}

func TestRealParameters(t *testing.T) {
	t.Skip()

	var rdl, err = NewRefDataLookup("https://refdatabase.refdata.ch/Service/Partner.asmx", time.Second*10, log.NewNopLogger())
	assert.Nil(t, err)

	initGln()

	var gln = choose(activeNumbers)
	t.Run("Active number "+gln, func(t *testing.T) {
		var details = rdl.Lookup(gln)
		assert.Nil(t, details.Error)
		assert.Len(t, details.Persons, 1)
		assert.True(t, *details.Persons[0].Active)
		assert.NotNil(t, details.Persons[0].FirstName)
	})
	gln = gln + "1"
	t.Run("Number with invalid format "+gln, func(t *testing.T) {
		var details = rdl.Lookup(gln)
		assert.Equal(t, ErrGLNNotFound, details.Error)
	})
	gln = choose(inactiveNumbers)
	t.Run("Inactive number "+gln, func(t *testing.T) {
		var details = rdl.Lookup(gln)
		assert.Nil(t, details.Error)
		assert.Len(t, details.Persons, 1)
		assert.False(t, *details.Persons[0].Active)
	})
	gln = "1601000281500"
	t.Run("Wrong number "+gln, func(t *testing.T) {
		var details = rdl.Lookup(gln)
		assert.Equal(t, ErrGLNNotFound, details.Error)
	})
}
