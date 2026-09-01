package main

import (
	app "github.com/signbyte/document-store"

	"azugo.io/azugo/server"
	"azugo.io/core/cli"
)

func init() {
	cli.Register(server.HealthCommand("/healthz", server.Options{
		AppName:       "Document Store Service",
		AppVer:        Version,
		Configuration: app.NewConfiguration(),
	}))
}
