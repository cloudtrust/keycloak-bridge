package keycloakb

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// GeneratePassword generates a password of a given length
func GeneratePassword(minLength int) string {

	var pwdElems []string
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ?!*0123456789"

	for j := 0; j < minLength; j++ {
		pwdElems = append(pwdElems, string(alphabet[rand.Intn(len(alphabet))]))
	}

	pwd := strings.Join(pwdElems, "")
	return pwd
}

// GeneratePasswordFromKeycloakPolicy generates a random password respecting the keycloak password policy
func GeneratePasswordFromKeycloakPolicy(policy string, minLength int) (string, error) {
	// Keycloak password policy is a string of the form
	// "forceExpiredPasswordChange(365) and specialChars(1) and upperCase(1) and lowerCase(1) and length(4) and digits(1) and notUsername(undefined)"
	var pwdElems []string
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
		case "length": // the minimum length of the password
			minLength, err := strconv.Atoi(keyValueItem[1])
			if err == nil {
				const lowerCase = "abcdefghijklmnopqrstuvwxyz"
				for j := 0; j < minLength; j++ {
					// make sure that the password has the minimum length required by choosing random lower case letters
					pwdElems = append(pwdElems, string(lowerCase[rand.Intn(len(lowerCase))]))
					fmt.Println(pwdElems)
				}
			} else {
				return "", err
			}
		}
	}

	rand.Seed(time.Now().Unix())
	for i := 0; i < len(policyItems); i++ {
		keyValueItem := strings.FieldsFunc(policyItems[i], f)
		switch keyValueItem[0] {
		case "specialChars":
			// pick randomly special characters from ?!#%$
			fmt.Println("specialChars")
			minRequired, err := strconv.Atoi(keyValueItem[1])
			if err == nil {
				specialChars := []string{"?", "!", "#", "%", "$"}
				for j := 0; j < minRequired; j++ {
					pwdElems = append(pwdElems, specialChars[rand.Intn(len(specialChars))])
					fmt.Println(pwdElems)
				}
			} else {
				return "", err
			}

		case "upperCase":
			fmt.Println("upperCase")
			minRequired, err := strconv.Atoi(keyValueItem[1])
			if err == nil {
				const upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				for j := 0; j < minRequired; j++ {
					pwdElems = append(pwdElems, string(upperCase[rand.Intn(len(upperCase))]))
					fmt.Println(pwdElems)
				}
			} else {
				return "", err
			}

		case "digits":
			fmt.Println("digits")
			minRequired, err := strconv.Atoi(keyValueItem[1])
			if err == nil {
				for j := 0; j < minRequired; j++ {
					pwdElems = append(pwdElems, strconv.Itoa(rand.Intn(10)))
					fmt.Println(pwdElems)
				}
			} else {
				return "", err
			}
		}

	}
	rand.Shuffle(len(pwdElems), func(i, j int) { pwdElems[i], pwdElems[j] = pwdElems[j], pwdElems[i] })
	pwd := strings.Join(pwdElems, "")
	fmt.Println(pwd)
	return pwd, nil

}
