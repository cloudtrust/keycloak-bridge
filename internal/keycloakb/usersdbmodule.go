package keycloakb

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/cloudtrust/common-service/database/sqltypes"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/security"
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
	selectCheckStmt = `
	  SELECT check_id, realm_id, user_id, operator, unix_timestamp(datetime), status, type, nature, proof_type, proof_data, comment
	  FROM checks
	  WHERE realm_id=?
		AND user_id=?;`
)

// UsersDBModule interface
type UsersDBModule interface {
	StoreOrUpdateUser(ctx context.Context, realm string, user dto.DBUser) error
	GetUser(ctx context.Context, realm string, userID string) (*dto.DBUser, error)
	CreateCheck(ctx context.Context, realm string, userID string, check dto.DBCheck) error
	GetUserChecks(ctx context.Context, realm string, userID string) ([]dto.DBCheck, error)
}

type usersDBModule struct {
	db     sqltypes.CloudtrustDB
	cipher security.CrypterDecrypter
	logger log.Logger
}

func nullStringToPtr(value sql.NullString) *string {
	if value.Valid {
		return &value.String
	}
	return nil
}

func nullStringToDatePtr(value sql.NullString) *time.Time {
	if value.Valid {
		var dateInt, _ = strconv.ParseInt(strings.Split(value.String, ".")[0], 10, 64)
		var date = time.Unix(int64(dateInt), 0)
		return &date
	}
	return nil
}

// NewUsersDBModule returns a UsersDB module.
func NewUsersDBModule(db sqltypes.CloudtrustDB, cipher security.CrypterDecrypter, logger log.Logger) UsersDBModule {
	return &usersDBModule{
		db:     db,
		cipher: cipher,
		logger: logger,
	}
}

func (c *usersDBModule) StoreOrUpdateUser(ctx context.Context, realm string, user dto.DBUser) error {
	// transform user object into JSON string
	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}
	// encrypt the JSON containing the details on the user
	encryptedData, err := c.cipher.Encrypt(userJSON, nil)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't encrypt the user details", "error", err.Error(), "realmID", realm, "userID", &user.UserID)
		return err
	}

	// update value in DB
	_, err = c.db.Exec(updateUserStmt, realm, user.UserID, encryptedData, encryptedData)
	return err
}

func (c *usersDBModule) GetUser(ctx context.Context, realm string, userID string) (*dto.DBUser, error) {
	var encryptedDetails []byte
	var details = dto.DBUser{}
	row := c.db.QueryRow(selectUserStmt, realm, userID)

	switch err := row.Scan(&encryptedDetails); err {
	case sql.ErrNoRows:
		return nil, nil
	default:
		if err != nil {
			return nil, err
		}
		//decrypt the user details & unmarshal
		detailsJSON, err := c.cipher.Decrypt(encryptedDetails, nil)
		if err != nil {
			c.logger.Warn(ctx, "msg", "Can't decrypt the user details", "error", err.Error(), "realmID", realm, "userID", userID)
			return nil, err
		}
		err = json.Unmarshal(detailsJSON, &details)
		details.UserID = &userID
		return &details, err
	}
}

func (c *usersDBModule) CreateCheck(ctx context.Context, realm string, userID string, check dto.DBCheck) error {
	// encrypt the proof data & protect integrity of userID associated to the proof data
	encryptedData, err := c.cipher.Encrypt(*check.ProofData, []byte(userID))
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't encrypt the proof data", "error", err.Error(), "realmID", realm, "userID", userID)
		return err
	}
	// insert check in DB
	_, err = c.db.Exec(createCheckStmt, realm, userID, check.Operator,
		check.DateTime, check.Status, check.Type, check.Nature,
		check.ProofType, encryptedData, check.Comment)

	return err
}

func (c *usersDBModule) GetUserChecks(ctx context.Context, realm string, userID string) ([]dto.DBCheck, error) {
	var rows, err = c.db.Query(selectCheckStmt, realm, userID)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	var result []dto.DBCheck
	var checkID int64
	var operator, datetime, status, checkType, nature, proofType, comment sql.NullString
	var proofData []byte

	for rows.Next() {
		err = rows.Scan(&checkID, &realm, &userID, &operator, &datetime, &status, &checkType, &nature, &proofType, &proofData, &comment)
		if err != nil {
			return nil, err
		}
		result = append(result, dto.DBCheck{
			Operator:  nullStringToPtr(operator),
			DateTime:  nullStringToDatePtr(datetime),
			Status:    nullStringToPtr(status),
			Type:      nullStringToPtr(checkType),
			Nature:    nullStringToPtr(nature),
			ProofData: &proofData,
			ProofType: nullStringToPtr(proofType),
			Comment:   nullStringToPtr(comment),
		})
	}

	return result, err
}
