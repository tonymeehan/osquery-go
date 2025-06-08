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

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/prequel-dev/preq/pkg/cli"
)

var (
	socketPath = flag.String("socket", "", "Path to osquery extension socket")
)

func main() {
	flag.Parse()
	if *socketPath == "" {
		log.Fatalf("Missing required --socket flag")
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
