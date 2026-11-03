package backup

import (
	"fmt"
	"strings"
)

// DBTarget is a project database running as a local container (capsule-db-<id>).
type DBTarget struct {
	Container string
	Engine    string
	DBName    string
	User      string
	Password  string
}

// engine knows how to dump/restore one database engine inside its container.
// Dumps stream to stdout; restores read stdin. Passwords only travel in Env.
type engine struct {
	ext     string
	dump    func(t DBTarget) Cmd
	restore func(t DBTarget, target string) (Cmd, error) // nil => restore unsupported
	create  func(t DBTarget, target string) Cmd          // create the target database (restore into new)
	drop    func(t DBTarget, target string) Cmd          // drop it when the restore fails
	list    func(t DBTarget) *Cmd                        // integrity listing for verify (postgres only)
}

const unsupportedMsg = "engine %q is not supported for backups (supported: postgres, mysql, mariadb, mongodb, redis)"

func engineFor(name string) (*engine, error) {
	switch name {
	case "postgres":
		return postgresEngine, nil
	case "mysql", "mariadb":
		return mysqlEngine, nil
	case "mongodb":
		return mongoEngine, nil
	case "redis":
		return redisEngine, nil
	}
	return nil, fmt.Errorf(unsupportedMsg, name)
}

// execArgs builds `docker exec [-i] -e NAME... container prog...`. Env entries are KEY=VALUE;
// only the NAME reaches argv, the value travels in the docker client's environment.
func execArgs(container string, stdin bool, env []string, prog ...string) []string {
	a := []string{"exec"}
	if stdin {
		a = append(a, "-i")
	}
	for _, e := range env {
		a = append(a, "-e", e[:strings.IndexByte(e, '=')])
	}
	a = append(a, container)
	return append(a, prog...)
}

func pgEnv(t DBTarget) []string { return []string{"PGPASSWORD=" + t.Password} }

var postgresEngine = &engine{
	ext: "pgdump",
	dump: func(t DBTarget) Cmd {
		return Cmd{Env: pgEnv(t), Args: execArgs(t.Container, false, pgEnv(t),
			"pg_dump", "--format=custom", "-U", t.User, "-d", t.DBName)}
	},
	restore: func(t DBTarget, target string) (Cmd, error) {
		if target != "" {
			return Cmd{Env: pgEnv(t), Args: execArgs(t.Container, true, pgEnv(t),
				"pg_restore", "--no-owner", "--exit-on-error", "-U", t.User, "-d", target)}, nil
		}
		// --single-transaction: a failed restore rolls back and leaves the database untouched.
		return Cmd{Env: pgEnv(t), Args: execArgs(t.Container, true, pgEnv(t),
			"pg_restore", "--clean", "--if-exists", "--no-owner", "--single-transaction", "--exit-on-error",
			"-U", t.User, "-d", t.DBName)}, nil
	},
	create: func(t DBTarget, target string) Cmd {
		return Cmd{Env: pgEnv(t), Args: execArgs(t.Container, false, pgEnv(t),
			"psql", "-U", t.User, "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", `CREATE DATABASE "`+target+`"`)}
	},
	drop: func(t DBTarget, target string) Cmd {
		return Cmd{Env: pgEnv(t), Args: execArgs(t.Container, false, pgEnv(t),
			"psql", "-U", t.User, "-d", "postgres", "-c", `DROP DATABASE IF EXISTS "`+target+`"`)}
	},
	list: func(t DBTarget) *Cmd {
		return &Cmd{Args: execArgs(t.Container, true, nil, "pg_restore", "--list")}
	},
}

// mysql/mariadb: the binary name differs by image version, so a tiny sh wrapper picks it.
// Arguments are positional ("$@"), never interpolated into the script.
func mysqlWrap(candidates string) []string {
	return []string{"sh", "-c", `for b in ` + candidates + `; do command -v "$b" >/dev/null 2>&1 && exec "$b" "$@"; done; echo "no client binary found" >&2; exit 127`, "sh"}
}

func myEnv(t DBTarget) []string { return []string{"MYSQL_PWD=" + t.Password} }

var mysqlEngine = &engine{
	ext: "sql",
	dump: func(t DBTarget) Cmd {
		prog := append(mysqlWrap("mysqldump mariadb-dump"),
			"--single-transaction", "--no-tablespaces", "--routines", "--triggers", "-u", t.User, t.DBName)
		return Cmd{Env: myEnv(t), Args: execArgs(t.Container, false, myEnv(t), prog...)}
	},
	restore: func(t DBTarget, target string) (Cmd, error) {
		user, db := t.User, t.DBName
		if target != "" {
			user, db = "root", target // capsuleadmin cannot create databases; root shares the password
		}
		prog := append(mysqlWrap("mysql mariadb"), "-u", user, db)
		return Cmd{Env: myEnv(t), Args: execArgs(t.Container, true, myEnv(t), prog...)}, nil
	},
	create: func(t DBTarget, target string) Cmd {
		prog := append(mysqlWrap("mysql mariadb"), "-u", "root", "-e", "CREATE DATABASE `"+target+"`")
		return Cmd{Env: myEnv(t), Args: execArgs(t.Container, false, myEnv(t), prog...)}
	},
	drop: func(t DBTarget, target string) Cmd {
		prog := append(mysqlWrap("mysql mariadb"), "-u", "root", "-e", "DROP DATABASE IF EXISTS `"+target+"`")
		return Cmd{Env: myEnv(t), Args: execArgs(t.Container, false, myEnv(t), prog...)}
	},
}

func mongoEnv(t DBTarget) []string { return []string{"MU=" + t.User, "MP=" + t.Password} }

const mongoURI = `mongodb://$MU:$MP@127.0.0.1:27017/?authSource=admin`

var mongoEngine = &engine{
	ext: "archive.gz",
	dump: func(t DBTarget) Cmd {
		return Cmd{Env: mongoEnv(t), Args: execArgs(t.Container, false, mongoEnv(t),
			"sh", "-c", `exec mongodump --uri="`+mongoURI+`" --db "$1" --archive --gzip`, "sh", t.DBName)}
	},
	restore: func(t DBTarget, target string) (Cmd, error) {
		script := `exec mongorestore --uri="` + mongoURI + `" --archive --gzip --drop --nsInclude "$1.*"`
		args := []string{"sh", "-c", script, "sh", t.DBName}
		if target != "" { // mongo creates databases lazily: no create step
			script = `exec mongorestore --uri="` + mongoURI + `" --archive --gzip --nsInclude "$1.*" --nsFrom "$1.*" --nsTo "$2.*"`
			args = []string{"sh", "-c", script, "sh", t.DBName, target}
		}
		return Cmd{Env: mongoEnv(t), Args: execArgs(t.Container, true, mongoEnv(t), args...)}, nil
	},
	drop: func(t DBTarget, target string) Cmd {
		return Cmd{Env: mongoEnv(t), Args: execArgs(t.Container, false, mongoEnv(t),
			"sh", "-c", `exec mongosh "`+mongoURI+`" --quiet --eval "db.getSiblingDB('$1').dropDatabase()"`, "sh", target)}
	},
}

// redis: the managed container runs without a password (the image ignores REDIS_PASSWORD),
// so `redis-cli --rdb -` takes a consistent point-in-time RDB over the replication protocol.
// Restore is deliberately unsupported (it requires stopping the server and replacing dump.rdb).
var redisEngine = &engine{
	ext: "rdb",
	dump: func(t DBTarget) Cmd {
		return Cmd{Args: execArgs(t.Container, false, nil, "redis-cli", "--rdb", "-")}
	},
}
