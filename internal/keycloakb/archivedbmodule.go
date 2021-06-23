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
	storeUserArchiveStmt = `
	  INSERT users (realm_name, user_id, timestamp, details)
	  VALUES (?, ?, UTC_TIMESTAMP, ?)
	`
)

// ArchiveDBModule interface
type ArchiveDBModule interface {
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

func (a *archiveDBModule) StoreUserDetails(ctx context.Context, realm string, user dto.ArchiveUserRepresentation) error {
	details, err := json.Marshal(user)
	if err != nil {
		a.logger.Warn(ctx, "msg", "Can't marshal user to json", "err", err.Error(), "realmID", realm, "userID", user.ID)
		return err
	}

	// encrypt the JSON containing the details on the user
	encryptedData, err := a.cipher.Encrypt(details, []byte(*user.ID))
	if err != nil {
		a.logger.Warn(ctx, "msg", "Can't encrypt the user archive", "err", err.Error(), "realmID", realm, "userID", user.ID)
		return err
	}

	// update value in DB
	_, err = a.db.Exec(storeUserArchiveStmt, realm, user.ID, encryptedData)
	return err
}
