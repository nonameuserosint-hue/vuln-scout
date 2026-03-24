package main

import (
	"io"
	"net/http"
)

func proxy(target string) ([]byte, error) {
	resp, err := http.Get(target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
