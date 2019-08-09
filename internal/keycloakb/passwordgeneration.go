package keycloakb

import (
	"math/rand"
	"strconv"
	"strings"
	"unicode"
)

const (
	lowerCase = "abcdefghijklmnopqrstuvwxyz"
)

// appendCharacters appends a number of characters from a certain alphabet to a string array
func appendCharacters(pwdElems []string, alphabet string, length int) []string {

	for j := 0; j < length; j++ {
		pwdElems = append(pwdElems, string(alphabet[rand.Intn(len(alphabet))]))
	}
	return pwdElems
}

// GeneratePassword generates a password accoring to the policy or minimum length imposed
func GeneratePassword(policy *string, minLength int, userID string) (string, error) {
	var pwd string
	var err error

	// generate a pwd != userID
	for {
		if policy != nil {
			pwd, err = GeneratePasswordFromKeycloakPolicy(*policy)
		} else {
			pwd = GeneratePasswordNoKeycloakPolicy(minLength)
		}
		if pwd != userID {
			break
		}
	}

	return pwd, err
}

// GeneratePassword generates a password of a given length
func GeneratePasswordNoKeycloakPolicy(minLength int) string {

	var pwdElems []string
	pwdElems = appendCharacters(pwdElems, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ?!*0123456789", minLength)
	pwd := strings.Join(pwdElems, "")
	return pwd
}

// GeneratePasswordFromKeycloakPolicy generates a random password respecting the keycloak password policy
func GeneratePasswordFromKeycloakPolicy(policy string) (string, error) {
	// Keycloak password policy is a string of the form
	// "forceExpiredPasswordChange(365) and specialChars(1) and upperCase(1) and lowerCase(1) and length(4) and digits(1) and notUsername(undefined)"
	var pwdElems = make([]string, 0)
	policyItems := strings.Split(policy, "and")

	// generate a random password that corresponds to the password policy
	//reg := regexp.MustCompile(`[a-zA-z]+[(]{1}[0-9]+[)]{1}`)
	//pwdReq := string(reg.Find([]byte()))

	f := func(c rune) bool {
		return !unicode.IsLetter(c) && !unicode.IsNumber(c)
	}

	for i := 0; i < len(policyItems); i++ {
		keyValueItem := strings.FieldsFunc(policyItems[i], f)
		switch keyValueItem[0] {
		case "length", "lowerCase":
			minRequired, err := strconv.Atoi(keyValueItem[1])
			if err == nil {
				// make sure that the password has the minimum length required by choosing random lower case letters
				pwdElems = appendCharacters(pwdElems, "abcdefghijklmnopqrstuvwxyz", minRequired)
			} else {
				return "", err
			}
		case "specialChars":
			// pick randomly special characters from ?!#%$
			minRequired, err := strconv.Atoi(keyValueItem[1])
			if err == nil {
				pwdElems = appendCharacters(pwdElems, "?!#%$", minRequired)
			} else {
				return "", err
			}

		case "upperCase":
			minRequired, err := strconv.Atoi(keyValueItem[1])
			if err == nil {
				pwdElems = appendCharacters(pwdElems, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", minRequired)
			} else {
				return "", err
			}

		case "digits":
			minRequired, err := strconv.Atoi(keyValueItem[1])
			if err == nil {
				pwdElems = appendCharacters(pwdElems, "0123456789", minRequired)
			} else {
				return "", err
			}
		}

	}
	rand.Shuffle(len(pwdElems), func(i, j int) { pwdElems[i], pwdElems[j] = pwdElems[j], pwdElems[i] })
	pwd := strings.Join(pwdElems, "")
	return pwd, nil

}
