package keycloakb

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/cloudtrust/common-service/database/sqltypes"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
)

const (
	updateUserStmt = `INSERT INTO user_details (realm_id, user_id, details)
	  VALUES (?, ?, ?) 
	  ON DUPLICATE KEY UPDATE details=?;`
	selectUserStmt = `
	  SELECT details
	  FROM user_details
	  WHERE realm_id=?
		AND user_id=?;`
	createCheckStmt = `INSERT INTO checks (realm_id, user_id, operator, datetime, status, type, nature, proof_type, proof_data, comment)
	  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
)

// UsersDBModule interface
type UsersDBModule interface {
	StoreOrUpdateUser(ctx context.Context, realm string, user dto.DBUser) error
	GetUser(ctx context.Context, realm string, userID string) (*dto.DBUser, error)
	CreateCheck(ctx context.Context, realm string, userID string, check dto.DBCheck) error
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

func (c *usersDBModule) StoreOrUpdateUser(ctx context.Context, realm string, user dto.DBUser) error {
	// transform user object into JSON string
	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}

	// update value in DB
	_, err = c.db.Exec(updateUserStmt, realm, user.UserID, string(userJSON), string(userJSON))
	return err
}

func (c *usersDBModule) GetUser(ctx context.Context, realm string, userID string) (*dto.DBUser, error) {
	var detailsJSON string
	var details = dto.DBUser{}
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

func (c *usersDBModule) CreateCheck(ctx context.Context, realm string, userID string, check dto.DBCheck) error {
	// insert check in DB
	_, err := c.db.Exec(createCheckStmt, realm, userID, check.Operator,
		check.DateTime, check.Status, check.Type, check.Nature,
		check.ProofType, check.ProofData, check.Comment)
	return err
}
