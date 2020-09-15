package main

import (
	"net/http"
	"os"
	"path/filepath"
)

type spaHandler struct {
	staticPath string
	indexPath  string
}

func (h spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path, err := os.Getwd()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	dirPath := filepath.Join(path, h.staticPath)
	path = filepath.Join(dirPath, r.URL.Path)
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		http.ServeFile(w, r, filepath.Join(dirPath, h.indexPath))
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.FileServer(http.Dir(dirPath)).ServeHTTP(w, r)
}
