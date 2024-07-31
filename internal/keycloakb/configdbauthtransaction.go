package keycloakb

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/database/sqltypes"
)

// AuthorizationTransaction interface
type AuthorizationTransaction interface {
	Close() error
	Commit() error

	CreateAuthorizations(ctx context.Context, authz []configuration.Authorization) error
	RemoveAuthorizations(ctx context.Context, authz []configuration.Authorization) error
}

type authorizationTransaction struct {
	tx sqltypes.Transaction
}

// NewAuthorizationTransaction creates a new AuthorizationTransaction
func NewAuthorizationTransaction(tx sqltypes.Transaction) AuthorizationTransaction {
	return &authorizationTransaction{tx: tx}
}

func prepareRequestForMultipleRows(baseRequest string, nb int) (string, error) {
	var valuesKeyword = "VALUES "
	var queryStatementParts = strings.Split(baseRequest, valuesKeyword)
	if len(queryStatementParts) != 2 {
		return "", errors.New("SQL request should contain uppercase VALUES once and only once")
	}
	var repeatPattern = strings.TrimRight(queryStatementParts[1], ";")
	return fmt.Sprintf("%s%s%s%s", queryStatementParts[0], valuesKeyword, repeatPattern, strings.Repeat(","+repeatPattern, nb-1)), nil
}

func (at *authorizationTransaction) Close() error {
	return at.tx.Close()
}

func (at *authorizationTransaction) Commit() error {
	return at.tx.Commit()
}

func (at *authorizationTransaction) executeQuery(query string, args ...any) error {
	_, err := at.tx.Exec(query, args...)
	return err
}

func (at *authorizationTransaction) CreateAuthorizations(ctx context.Context, authz []configuration.Authorization) error {
	// 50 rows per actual DB request
	return at.createAuthorizationsMax(ctx, authz, 50)
}

func (at *authorizationTransaction) createAuthorizationsMax(ctx context.Context, authz []configuration.Authorization, maxRow int) error {
	if len(authz) == 0 {
		return nil
	}
	if len(authz) > maxRow {
		if err := at.createAuthorizationsMax(ctx, authz[0:maxRow], maxRow); err != nil {
			return err
		}
		return at.createAuthorizationsMax(ctx, authz[maxRow:], maxRow)
	}
	var query, err = prepareRequestForMultipleRows(createAuthzStmt, len(authz))
	if err != nil {
		return nil
	}

	var args []any
	for _, auth := range authz {
		args = append(args, nullableString(auth.RealmID), nullableString(auth.GroupName), nullableString(auth.Action),
			nullableString(auth.TargetRealmID), nullableString(auth.TargetGroupName))
	}

	return at.executeQuery(query, args...)
}

func (at *authorizationTransaction) RemoveAuthorizations(ctx context.Context, authz []configuration.Authorization) error {
	for _, auth := range authz {
		if err := deleteAuthorization(at.executeQuery, *auth.RealmID, *auth.GroupName, *auth.TargetRealmID, auth.TargetGroupName, *auth.Action); err != nil {
			return err
		}
	}
	return nil
}
