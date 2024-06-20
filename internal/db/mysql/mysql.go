package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/spf13/viper"
)

type MySQL struct {
	db               *sql.DB
	findUuidByIdStmt *sql.Stmt
}

func New(protocol string, host string, port uint, dbName string, user string, password string) (*MySQL, error) {
	c := mysql.Config{
		User:                 user,
		Passwd:               password,
		Net:                  protocol,
		Addr:                 fmt.Sprintf("%s:%d", host, port),
		DBName:               dbName,
		AllowNativePasswords: true,
		Collation:            "utf8mb4_unicode_ci",
	}
	db, err := sql.Open("mysql", c.FormatDSN())
	if err != nil {
		return nil, err
	}

	findUuidByIdStmt, err := db.Prepare(`
		SELECT uuid
		  FROM accounts
		 WHERE id = ?
		   AND status = 10
		 LIMIT 1
	 `)
	if err != nil {
		return nil, fmt.Errorf("unable to prepare find account's uuid by id query: %w", err)
	}

	return &MySQL{db, findUuidByIdStmt}, nil
}

func NewWithConfig(config *viper.Viper) (*MySQL, error) {
	config.SetDefault("db.mysql.user", "root")
	config.SetDefault("db.mysql.password", "")
	config.SetDefault("db.mysql.host", "localhost")
	config.SetDefault("db.mysql.port", 3306)
	config.SetDefault("db.mysql.protocol", "tcp")

	return New(
		config.GetString("db.mysql.protocol"),
		config.GetString("db.mysql.host"),
		config.GetUint("db.mysql.port"),
		config.GetString("db.mysql.database"),
		config.GetString("db.mysql.user"),
		config.GetString("db.mysql.password"),
	)
}

func (m *MySQL) FindUuidById(ctx context.Context, id int) (string, error) {
	var uuid string
	err := m.findUuidByIdStmt.QueryRowContext(ctx, id).Scan(&uuid)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	} else if err != nil {
		return "", fmt.Errorf("unable to query an uuid from mysql: %w", err)
	}

	return uuid, nil
}

func (m *MySQL) Ping(ctx context.Context) error {
	return m.db.PingContext(ctx)
}
