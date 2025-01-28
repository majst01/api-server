package test

import (
	"context"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	r "gopkg.in/rethinkdb/rethinkdb-go.v6"
)

func StartRethink(t testing.TB) (container testcontainers.Container, s *r.Session, err error) {
	ctx := context.Background()
	var log testcontainers.Logging
	if t != nil {
		log = testcontainers.TestLogger(t)
	}
	req := testcontainers.ContainerRequest{
		Image:        "rethinkdb:2.4.4-bookworm-slim",
		ExposedPorts: []string{"8080/tcp", "28015/tcp"},
		Env:          map[string]string{"RETHINKDB_PASSWORD": "rethink"},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("28015/tcp"),
		),
		Cmd: []string{"rethinkdb", "--bind", "all", "--directory", "/tmp", "--initial-password", "rethink", "--io-threads", "500"},
	}
	rtContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Logger:           log,
	})
	if err != nil {
		panic(err.Error())
	}
	ip, err := rtContainer.Host(ctx)
	if err != nil {
		return rtContainer, nil, err
	}
	port, err := rtContainer.MappedPort(ctx, "28015")
	if err != nil {
		return rtContainer, nil, err
	}
	session, err := r.Connect(r.ConnectOpts{
		Addresses: []string{ip + ":" + port.Port()},
		Database:  "metal",
		Username:  "admin",
		Password:  "rethink",
		MaxIdle:   10,
		MaxOpen:   20,
	})

	return rtContainer, session, err
}
