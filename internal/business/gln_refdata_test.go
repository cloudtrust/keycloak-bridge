package business

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudtrust/common-service/log"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

const (
	refDataResponse = `
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

type webServer struct {
}

func (ws *webServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Add("Content-Type", "text/xml; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	writer.Write([]byte(refDataResponse))
}

func TestLookup(t *testing.T) {
	var handler webServer
	r := mux.NewRouter()
	r.Handle("/Service/Partner.asmx", &handler)

	ts := httptest.NewServer(r)
	defer ts.Close()

	var rdl, err = NewRefDataLookup(ts.URL+"/Service/Partner.asmx", time.Second*10, log.NewNopLogger())
	assert.Nil(t, err)

	var details = rdl.Lookup("123456789")
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
}

func TestRealParameters(t *testing.T) {
	var rdl, err = NewRefDataLookup("https://refdatabase.refdata.ch/Service/Partner.asmx", time.Second*10, log.NewNopLogger())
	assert.Nil(t, err)

	var gln = choose(activeNumbers)
	t.Run("Active number "+gln, func(t *testing.T) {
		var details = rdl.Lookup(gln)
		assert.Nil(t, details.Error)
		assert.Len(t, details.Persons, 1)
		assert.True(t, *details.Persons[0].Active)
		assert.NotNil(t, details.Persons[0].FirstName)
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
