package keycloakb

import (
	"fmt"
	"math/rand"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAppendCharacters(t *testing.T) {

	rand.Seed(time.Now().Unix())
	var pwdElems []string
	var length int = rand.Intn(20)

	pwdElems = appendCharacters(pwdElems, lowerCase, length)
	assert.Equal(t, len(pwdElems), length)
	for i := 0; i < len(pwdElems); i++ {
		assert.Contains(t, lowerCase, pwdElems[i])
	}

	// empty password
	length = 0
	var emptypwdElem []string
	emptypwdElem = appendCharacters(emptypwdElem, lowerCase, length)
	assert.Empty(t, emptypwdElem)

}

func TestGeneratePasswordNoKeycloakPolicy(t *testing.T) {

	rand.Seed(time.Now().Unix())
	var length int = rand.Intn(20)

	pwd := GeneratePasswordNoKeycloakPolicy(length)
	assert.Equal(t, len(pwd), length)

	for i := 0; i < len(pwd); i++ {
		assert.Contains(t, alphabet, string(pwd[i]))
	}
}

func TestGeneratePassword(t *testing.T) {
	var definitionFormat = "forceExpiredPasswordChange(365) and specialChars(%d) and upperCase(%d) and lowerCase(%d) and length(%d) and digits(%d) and notUsername(undefined)"

	t.Run("Invalid policy syntax", func(t *testing.T) {
		_, err := GeneratePasswordFromKeycloakPolicy("upperCase(XX)")
		assert.NotNil(t, err)
	})

	t.Run("FromKeycloakPolicy", func(t *testing.T) {
		var nospecialChars = 3
		var noupperCase = 2
		var nolowerCase = 3
		var length = 10
		var nodigits = 1
		var policy = fmt.Sprintf(definitionFormat, nospecialChars, noupperCase, nolowerCase, length, nodigits)

		regSpecialChars := regexp.MustCompile("[?!#%$]")
		regDigits := regexp.MustCompile("[0-9]")
		regUpperCase := regexp.MustCompile("[A-Z]")
		regLowerCase := regexp.MustCompile("[a-z]")

		pwd, err := GeneratePasswordFromKeycloakPolicy(policy)
		assert.Equal(t, len(regDigits.FindAllStringIndex(pwd, -1)), nodigits)
		assert.Equal(t, len(regLowerCase.FindAllStringIndex(pwd, -1)), nolowerCase+length)
		assert.Equal(t, len(regUpperCase.FindAllStringIndex(pwd, -1)), noupperCase)
		assert.Equal(t, len(regSpecialChars.FindAllStringIndex(pwd, -1)), nospecialChars)
		assert.True(t, len(pwd) >= length)
		assert.Equal(t, len(pwd), nodigits+nolowerCase+nospecialChars+noupperCase+length)
		assert.Nil(t, err)
	})

	var userID = "dummyID"
	var minLength = 3

	t.Run("GeneratePassword", func(t *testing.T) {
		var nospecialChars = 3
		var noupperCase = 2
		var nolowerCase = 3
		var length = 10
		var nodigits = 1
		var policy = fmt.Sprintf(definitionFormat, nospecialChars, noupperCase, nolowerCase, length, nodigits)

		pwd, err := GeneratePassword(&policy, minLength, userID)
		assert.Nil(t, err)
		assert.Equal(t, len(pwd), nodigits+nolowerCase+nospecialChars+noupperCase+length)

	})
	t.Run("GeneratePassword no policy", func(t *testing.T) {
		pwd, err := GeneratePassword(nil, minLength, userID)
		assert.Nil(t, err)
		assert.Equal(t, len(pwd), minLength)
	})
}

func TestGenerateInitialCode(t *testing.T) {
	var noupperCase = 1
	var nolowerCase = 1
	var nodigits = 6

	regDigits := regexp.MustCompile("[0-9]")
	regUpperCase := regexp.MustCompile("[A-Z]")
	regLowerCase := regexp.MustCompile("[a-z]")

	pwd := GenerateInitialCode(noupperCase, nodigits, nolowerCase)
	assert.Equal(t, len(pwd), nodigits+nolowerCase+noupperCase)
	assert.Equal(t, len(regDigits.FindAllStringIndex(pwd, -1)), nodigits)
	assert.Equal(t, len(regLowerCase.FindAllStringIndex(pwd, -1)), nolowerCase)
	assert.Equal(t, len(regUpperCase.FindAllStringIndex(pwd, -1)), noupperCase)
}
