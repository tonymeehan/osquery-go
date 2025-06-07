package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/prequel-dev/preq/pkg/cli"
)

var (
	socketPath = flag.String("socket", "", "Path to osquery extension socket")
	configPath = flag.String("config", "", "Path to preq config file")
	token      = flag.String("token", "", "JWT token for rule updates")
)

func main() {
	flag.Parse()
	if *socketPath == "" {
		log.Fatalf("Missing required --socket flag")
	}
	if *configPath == "" {
		log.Fatalf("Missing required --config flag")
	}
	if *token == "" {
		log.Fatalf("Missing required --token flag")
	}

	if err := setupEnv(*configPath, *token); err != nil {
		log.Fatalf("Failed to write token: %v", err)
	}

	server, err := osquery.NewExtensionManagerServer("preq", *socketPath)
	if err != nil {
		log.Fatalf("Error creating extension: %v", err)
	}

	plugin := table.NewPlugin("preq", columns(), generate)
	server.RegisterPlugin(plugin)

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func columns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("timestamp"),
		table.TextColumn("cre_id"),
		table.TextColumn("message"),
	}
}

func setupEnv(cfg, tok string) error {
	home := filepath.Dir(cfg)
	confDir := filepath.Join(home, ".config", "preq")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		return err
	}
	data, err := os.ReadFile(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(confDir, "config.yaml"), data, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(confDir, ".ruletoken"), []byte(tok), 0600); err != nil {
		return err
	}
	return os.Setenv("HOME", home)
}

func generate(ctx context.Context, qc table.QueryContext) ([]map[string]string, error) {
	cli.Options.Name = "-"
	cli.Options.Quiet = true
	cli.Options.AcceptUpdates = true
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stdout := os.Stdout
	os.Stdout = w

	outCh := make(chan []byte)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outCh <- buf.Bytes()
	}()

	if err := cli.InitAndExecute(ctx); err != nil {
		w.Close()
		os.Stdout = stdout
		<-outCh
		return nil, err
	}

	w.Close()
	os.Stdout = stdout
	out := <-outCh
	var report []map[string]any
	if err := json.Unmarshal(out, &report); err != nil {
		return []map[string]string{{"timestamp": "", "cre_id": "", "message": string(out)}}, nil
	}
	rows := make([]map[string]string, 0, len(report))
	for _, entry := range report {
		rows = append(rows, map[string]string{
			"timestamp": fmt.Sprintf("%v", entry["timestamp"]),
			"cre_id":    fmt.Sprintf("%v", entry["id"]),
			"message":   fmt.Sprintf("%v", entry["cre"]),
		})
	}
	return rows, nil
}
