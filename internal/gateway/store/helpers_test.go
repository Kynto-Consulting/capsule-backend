package store

import "github.com/jackc/pgx/v5"

func errNoRows() error { return pgx.ErrNoRows }
