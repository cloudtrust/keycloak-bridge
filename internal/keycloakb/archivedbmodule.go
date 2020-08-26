package keycloakb

import (
	"context"
	"encoding/json"

	"github.com/cloudtrust/common-service/database/sqltypes"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/security"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
)

const (
	getUserArchiveStmt = `
	  SELECT timestamp, details
	  FROM users
	  WHERE realm_name=? and user_id=?
	  ORDER BY timestamp desc
	`
	storeUserArchiveStmt = `
	  INSERT users (realm_name, user_id, timestamp, details)
	  VALUES (?, ?, UTC_TIMESTAMP, ?)
	`
)

// ArchiveDBModule interface
type ArchiveDBModule interface {
	GetUserDetails(ctx context.Context, realm string, userID string) ([]dto.ArchiveUserRepresentation, error)
	StoreUserDetails(ctx context.Context, realm string, user dto.ArchiveUserRepresentation) error
}

type archiveDBModule struct {
	db     sqltypes.CloudtrustDB
	cipher security.EncrypterDecrypter
	logger log.Logger
}

// NewArchiveDBModule returns an archive DB module.
func NewArchiveDBModule(db sqltypes.CloudtrustDB, cipher security.EncrypterDecrypter, logger log.Logger) ArchiveDBModule {
	return &archiveDBModule{
		db:     db,
		cipher: cipher,
		logger: logger,
	}
}

func (a *archiveDBModule) GetUserDetails(ctx context.Context, realm string, userID string) ([]dto.ArchiveUserRepresentation, error) {
	var rows, err = a.db.Query(getUserArchiveStmt, realm, userID)
	if err != nil {
		a.logger.Warn(ctx, "msg", "Can't read user rows", "error", err.Error(), "realmID", realm, "userID", userID)
		return nil, err
	}
	defer rows.Close()

	var res []dto.ArchiveUserRepresentation
	for rows.Next() {
		var timestamp, encryptedDetails string
		if err = rows.Scan(&timestamp, &encryptedDetails); err != nil {
			a.logger.Warn(ctx, "msg", "Can't fetch row", "error", err.Error(), "realmID", realm, "userID", userID)
			return nil, err
		}
		var bytes, err = a.cipher.Decrypt([]byte(encryptedDetails), []byte(userID))
		if err != nil {
			a.logger.Warn(ctx, "msg", "Can't decrypt user details", "error", err.Error(), "realmID", realm, "userID", userID)
			return nil, err
		}
		var details dto.ArchiveUserRepresentation
		if err = json.Unmarshal(bytes, &details); err != nil {
			a.logger.Warn(ctx, "msg", "Can't unmarshal user details", "error", err.Error(), "realmID", realm, "userID", userID)
			return nil, err
		}
		res = append(res, details)
	}

	return res, nil
}

func (a *archiveDBModule) StoreUserDetails(ctx context.Context, realm string, user dto.ArchiveUserRepresentation) error {
	details, err := json.Marshal(user)
	if err != nil {
		a.logger.Warn(ctx, "msg", "Can't marshal user to json", "error", err.Error(), "realmID", realm, "userID", user.ID)
		return err
	}

	// encrypt the JSON containing the details on the user
	encryptedData, err := a.cipher.Encrypt(details, []byte(*user.ID))
	if err != nil {
		a.logger.Warn(ctx, "msg", "Can't encrypt the user archive", "error", err.Error(), "realmID", realm, "userID", user.ID)
		return err
	}

	// update value in DB
	_, err = a.db.Exec(storeUserArchiveStmt, realm, user.ID, encryptedData)
	return err
}
