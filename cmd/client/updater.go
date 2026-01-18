package main

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func compareVersions(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")

	for i := 0; i < max(len(as), len(bs)); i++ {
		ai := 0
		if i < len(as) {
			ai, _ = strconv.Atoi(as[i])
		}
		bi := 0
		if i < len(bs) {
			bi, _ = strconv.Atoi(bs[i])
		}

		if ai > bi {
			return 1
		}
		if ai < bi {
			return -1
		}
	}
	return 0
}

func CheckAndUpdate() error {
	resp, err := http.Get(
		"https://api.github.com/repos/" + RepoOwner + "/" + RepoName + "/releases",
	)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github api returned %s", resp.Status)
	}
	defer resp.Body.Close()

	var releases []release
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return err
	}

	var commercial *release
	for i := range releases {
		if releases[i].TagName == "commercial" {
			commercial = &releases[i]
			break
		}
	}

	if commercial == nil {
		return errors.New(`release with tag "commercial" not found`)
	}

	var assetName, downloadURL string
	for _, a := range commercial.Assets {
		if strings.HasPrefix(a.Name, runtime.GOOS+".") && strings.HasSuffix(a.Name, ".zip") {
			assetName = a.Name
			downloadURL = a.URL
			break
		}
	}

	if downloadURL == "" {
		return errors.New("can not find the github asset to update")
	}

	remoteVersion, err := extractVersion(assetName)
	if err != nil {
		return err
	}
	if compareVersions(remoteVersion, CurrentVersion) <= 0 {
		return nil
	}

	archiveName := runtime.GOOS + "." + remoteVersion + ".zip"

	tmpZip := filepath.Join(os.TempDir(), archiveName)
	if err := downloadFile(tmpZip, downloadURL); err != nil {
		return err
	}

	if err := applyUpdate(tmpZip); err != nil {
		return err
	}

	os.Exit(0)
	return nil
}

func downloadFile(dst, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func applyUpdate(zipPath string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	exe, _ := os.Executable()

	for _, f := range r.File {
		dst := filepath.Join(filepath.Dir(exe), f.Name)

		if f.FileInfo().IsDir() {
			os.MkdirAll(dst, 0755)
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		tmp := dst + ".new"
		out, err := os.Create(tmp)
		if err != nil {
			rc.Close()
			return err
		}

		io.Copy(out, rc)
		out.Close()
		rc.Close()

		os.Rename(tmp, dst)
	}
	return nil
}

func extractVersion(assetName string) (string, error) {
	base := strings.TrimSuffix(assetName, ".zip")
	parts := strings.Split(base, ".")
	if len(parts) < 2 {
		return "", errors.New("invalid asset name")
	}
	return strings.Join(parts[1:], "."), nil
}
