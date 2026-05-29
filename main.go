package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		fmt.Fprintf(w, "backend received request\n")
		fmt.Fprintf(w, "method: %s\n", r.Method)
		fmt.Fprintf(w, "path: %s\n", r.URL.Path)
		fmt.Fprintf(w, "query: %s\n", r.URL.RawQuery)
		fmt.Fprintf(w, "body: %s\n", string(body))
	})

	slog.Info("test backend listening", "addr", ":8081")
	if err := http.ListenAndServe(":8081", handler); err != nil {
		slog.Error("test backend listen error", "error", err)
		os.Exit(1)
	}
}
