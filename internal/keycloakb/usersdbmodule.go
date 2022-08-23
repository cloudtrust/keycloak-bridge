package keycloakb

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/cloudtrust/common-service/v2/database/sqltypes"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
)

const (
	updateUserDetailsStmt = `INSERT INTO user_details (realm_id, user_id, details, key_id)
	  VALUES (?, ?, ?, ?) 
	  ON DUPLICATE KEY UPDATE details=?, key_id=?;`
	selectUserDetailsStmt = `
	  SELECT details, key_id
	  FROM user_details
	  WHERE realm_id=?
		AND user_id=?;`
	deleteUserDetailsStmt = `DELETE FROM user_details WHERE realm_id=? AND user_id=?;`
)

// UsersDetailsDBModule interface
type UsersDetailsDBModule interface {
	StoreOrUpdateUserDetails(ctx context.Context, realm string, user dto.DBUser) error
	GetUserDetails(ctx context.Context, realm string, userID string) (dto.DBUser, error)
	DeleteUserDetails(ctx context.Context, realm string, userID string) error
}

type usersDBModule struct {
	db     sqltypes.CloudtrustDB
	cipher security.EncrypterDecrypter
	logger log.Logger
}

// NewUsersDetailsDBModule returns a UsersDB module.
func NewUsersDetailsDBModule(db sqltypes.CloudtrustDB, cipher security.EncrypterDecrypter, logger log.Logger) UsersDetailsDBModule {
	return &usersDBModule{
		db:     db,
		cipher: cipher,
		logger: logger,
	}
}

func (c *usersDBModule) StoreOrUpdateUserDetails(ctx context.Context, realm string, user dto.DBUser) error {
	// transform user object into JSON string
	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}
	// encrypt the JSON containing the details on the user
	encryptedData, err := c.cipher.Encrypt(userJSON, []byte(*user.UserID))
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't encrypt the user details", "err", err.Error(), "realmID", realm, "userID", &user.UserID)
		return err
	}

	keyID := c.cipher.GetCurrentKeyID()
	// update value in DB
	_, err = c.db.Exec(updateUserDetailsStmt, realm, user.UserID, encryptedData, keyID, encryptedData, keyID)
	return err
}

func (c *usersDBModule) GetUserDetails(ctx context.Context, realm string, userID string) (dto.DBUser, error) {
	var encryptedDetails []byte
	var keyID string
	var details = dto.DBUser{}
	row := c.db.QueryRow(selectUserDetailsStmt, realm, userID)

	switch err := row.Scan(&encryptedDetails, &keyID); err {
	case sql.ErrNoRows:
		return dto.DBUser{
			UserID: &userID,
		}, nil
	default:
		if err != nil {
			return dto.DBUser{}, err
		}
		//decrypt the user details & unmarshal
		detailsJSON, err := c.cipher.Decrypt(encryptedDetails, keyID, []byte(userID))
		if err != nil {
			c.logger.Warn(ctx, "msg", "Can't decrypt the user details", "err", err.Error(), "realmID", realm, "userID", userID)
			return dto.DBUser{}, err
		}
		err = json.Unmarshal(detailsJSON, &details)
		details.UserID = &userID
		return details, err
	}
}

func (c *usersDBModule) DeleteUserDetails(ctx context.Context, realm string, userID string) error {
	_, err := c.db.Exec(deleteUserDetailsStmt, realm, userID)
	return err
}
