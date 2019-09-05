package account

import (
	"errors"
	"regexp"

	kc "github.com/cloudtrust/keycloak-client"
)

// UserRepresentation struct
type AccountRepresentation struct {
	Username    *string `json:"username,omitempty"`
	Email       *string `json:"email,omitempty"`
	FirstName   *string `json:"firstName,omitempty"`
	LastName    *string `json:"lastName,omitempty"`
	PhoneNumber *string `json:"phoneNumber,omitempty"`
}

// ConvertToAPIAccount creates an API account representation from  a KC user representation
func ConvertToAPIAccount(userKc kc.UserRepresentation) AccountRepresentation {
	var userRep AccountRepresentation

	userRep.Username = userKc.Username
	userRep.Email = userKc.Email
	userRep.FirstName = userKc.FirstName
	userRep.LastName = userKc.LastName

	if userKc.Attributes != nil {
		var m = *userKc.Attributes

		if m["phoneNumber"] != nil {
			var phoneNumber = m["phoneNumber"][0]
			userRep.PhoneNumber = &phoneNumber
		}
	}
	return userRep
}

// ConvertToKCUser creates a KC user representation from an API user
func ConvertToKCUser(user AccountRepresentation) kc.UserRepresentation {
	var userRep kc.UserRepresentation

	userRep.Username = user.Username
	userRep.Email = user.Email
	userRep.FirstName = user.FirstName
	userRep.LastName = user.LastName

	var attributes = make(map[string][]string)

	if user.PhoneNumber != nil {
		attributes["phoneNumber"] = []string{*user.PhoneNumber}
	}

	if len(attributes) > 0 {
		userRep.Attributes = &attributes
	}

	return userRep
}

// Validators

// Validate is a validator for AccountRepresentation
func (user AccountRepresentation) Validate() error {
	if user.Username != nil && !matchesRegExp(*user.Username, RegExpUsername) {
		return errors.New("Invalid username")
	}

	if user.Email != nil && !matchesRegExp(*user.Email, RegExpEmail) {
		return errors.New("Invalid email")
	}

	if user.FirstName != nil && !matchesRegExp(*user.FirstName, RegExpFirstName) {
		return errors.New("Invalid firstname")
	}

	if user.LastName != nil && !matchesRegExp(*user.LastName, RegExpLastName) {
		return errors.New("Invalid lastname")
	}

	if user.PhoneNumber != nil && !matchesRegExp(*user.PhoneNumber, RegExpPhoneNumber) {
		return errors.New("Invalid phone number")
	}

	return nil
}

func matchesRegExp(value, re string) bool {
	res, _ := regexp.MatchString(re, value)
	return res
}

// Regular expressions for parameters validation
const (
	// User
	RegExpUsername    = `^[a-zA-Z0-9-_.]{1,128}$`
	RegExpEmail       = `^.+\@.+\..+`
	RegExpFirstName   = `^.{1,128}$`
	RegExpLastName    = `^.{1,128}$`
	RegExpPhoneNumber = `^\+[1-9]\d{1,14}$`
)
