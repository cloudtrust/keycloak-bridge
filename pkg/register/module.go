package register

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/cloudtrust/common-service/log"
	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"

	"github.com/cloudtrust/common-service/database/sqltypes"
)

const (
	updateUserStmt = `INSERT INTO user_details (realm_id, user_id, details)
	  VALUES (?, ?, ?) 
	  ON DUPLICATE KEY UPDATE details=?;`
	selectUserStmt = `
	  SELECT details
	  FROM user_details
	  WHERE realm_id=?
		AND user_id=?
	`
)

// UsersDBModule interface
type UsersDBModule interface {
	StoreOrUpdateUser(ctx context.Context, realm string, user apiregister.DBUser) error
	GetUser(ctx context.Context, realm string, userID string) (*apiregister.DBUser, error)
}

type usersDBModule struct {
	db     sqltypes.CloudtrustDB
	logger log.Logger
}

// NewUsersDBModule returns a UsersDB module.
func NewUsersDBModule(db sqltypes.CloudtrustDB, logger log.Logger) UsersDBModule {
	return &usersDBModule{
		db:     db,
		logger: logger,
	}
}

func (c *usersDBModule) StoreOrUpdateUser(ctx context.Context, realm string, user apiregister.DBUser) error {
	// transform user object into JSON string
	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}

	// update value in DB
	_, err = c.db.Exec(updateUserStmt, realm, user.UserID, string(userJSON), string(userJSON))
	return err
}

func (c *usersDBModule) GetUser(ctx context.Context, realm string, userID string) (*apiregister.DBUser, error) {
	var detailsJSON string
	var details = apiregister.DBUser{}
	row := c.db.QueryRow(selectUserStmt, realm, userID)

	switch err := row.Scan(&detailsJSON); err {
	case sql.ErrNoRows:
		return nil, nil
	default:
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal([]byte(detailsJSON), &details)
		details.UserID = &userID
		return &details, err
	}
}