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
	<table id="tblSearch">   <tr class="searchFieldCaption"><td colspan="2">
   GLN
   </td></tr><tr class="searchField">
        <td colspan="2"><input id="SearchGln" name="SearchGln" onkeyup="if(event.keyCode == 13)$(&#39;#BtnSearchByGln&#39;).click();" type="text" value="7601000001726" />
        </td></tr>    <tr>
        <td colspan="2"><br/><input type="button" id="BtnSearchByGln" value="Rechercher" onclick="SearchByGln()" /><input type="button" id="BtnResetByGln" value="Reset" onclick="ResetByGln()" /></td></tr></table>
		<div id="pnlResult"><table style="width:100%"><tr valign="bottom"><td align="left"><strong></strong></td><td align="right">Statut: A=Actif / I=Inactif</td></tr></table>
        <table cellspacing="0" cellpadding="4" id="GVResult" style="width:100%;border-collapse:collapse;">
            <thead><tr class="dgHeader">
                    <th scope="col"><a onclick="">GLN</a></th>
                    <th scope="col"><a onclick="">Statut</a></th>
                    <th scope="col"><a onclick="">Langue</a></th>
                    <th scope="col"><a onclick="">Nom</a></th>
                    <th scope="col"><a onclick="">Pr&#233;nom</a></th>
                    <th scope="col"><a onclick="" title="IHP refdatabase code">Profession</a></th>
                    <th scope="col"><a onclick="">NPA</a> <a onclick="SortNat('City')">Localit&#233;</a></th>
                    <th scope="col"><a onclick="">Ctn</a></th>
                    <th scope="col"><a onclick="">Pays</a></th>
                </tr></thead><tbody class="dgRow status_A"><tr>
                                <td>111111111</td>
                                <td title="Depuis le 01.01.2006">A</td>
                                <td>FR</td>
                                <td>El Bichon</td>
                                <td>Marc</td>
                            <td title="M&#233;decin">DoctMed</td>
                            <td>1207 Genève</td>
                            <td>GE</td>
                            <td>CH</td>
                        </tr></tbody>
					<tbody class="dgRow status_A"><tr>
						<td>222222222</td>
						<td title="Depuis le 01.01.2006">A</td>
						<td>FR</td>
						<td>Ombrage</td>
						<td>Sophie</td>
					<td title="M&#233;decin">DoctMed</td>
					<td>1001 Lausanne</td>
					<td>VD</td>
					<td>CH</td>
				</tr></tbody></table></div>
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
	writer.Header().Add("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	writer.Write([]byte(refDataResponse))
}

func TestLookup(t *testing.T) {
	var handler webServer
	r := mux.NewRouter()
	r.Handle("/fr/partenaires/requete/base-de-donnees-des-partenaires-gln", &handler)
	r.Handle("/Viewer/SearchPartnerByGln", &handler)

	ts := httptest.NewServer(r)
	defer ts.Close()

	var rdl, err = NewRefDataLookup(ts.URL, time.Second*10, log.NewNopLogger())
	assert.Nil(t, err)

	var details = rdl.Lookup("123456789")
	assert.Nil(t, details.Error)
	assert.Len(t, details.Persons, 2)

	assert.Equal(t, "111111111", *details.Persons[0].Number)
	assert.Equal(t, "Marc", *details.Persons[0].FirstName)
	assert.Equal(t, "El Bichon", *details.Persons[0].LastName)
	assert.Equal(t, "1207", *details.Persons[0].ZipCode)
	assert.Equal(t, "Genève", *details.Persons[0].City)

	assert.Equal(t, "222222222", *details.Persons[1].Number)
	assert.Equal(t, "Sophie", *details.Persons[1].FirstName)
	assert.Equal(t, "Ombrage", *details.Persons[1].LastName)
	assert.Equal(t, "1001", *details.Persons[1].ZipCode)
	assert.Equal(t, "Lausanne", *details.Persons[1].City)
}

func TestRealParameters(t *testing.T) {
	var rdl, err = NewRefDataLookup("https://refdatabase.refdata.ch", time.Second*10, log.NewNopLogger())
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
