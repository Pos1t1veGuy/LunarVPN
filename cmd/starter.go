package main

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	RepoOwner = "Pos1t1veGuy"
	RepoName  = "LunarVPN"
)

type release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

type progressWriter struct {
	total   int64
	current int64
	lastPct int
}

func (pw *progressWriter) Write(b []byte) (int, error) {
	n := len(b)
	pw.current += int64(n)

	if pw.total > 0 {
		pct := int(float64(pw.current) / float64(pw.total) * 100)
		if pct != pw.lastPct {
			pw.lastPct = pct
			fmt.Printf("\rdownloading... %d%%", pct)
		}
	}

	return n, nil
}

func main() {
	exeDir, err := os.Executable()
	if err != nil {
		fmt.Println("Cannot get executable path:", err)
		return
	}
	exeDir = filepath.Dir(exeDir)

	app := "client"
	if runtime.GOOS == "windows" {
		app = "client.exe"
	}
	appPath := filepath.Join(exeDir, app)
	version, err := getClientVersion(appPath)
	if err != nil {
		fmt.Println("Can not get client version:", err)
		return
	}

	fmt.Println("checking updates...")
	updated, err := CheckAndUpdate(appPath, version)
	if err != nil {
		fmt.Println("auto update failed", err)
	} else if !updated {
		fmt.Println("application version is latest")
	} else {
		fmt.Println("application is updated and needs to be RESTARTED")
		return
	}
	err = run(appPath)
	if err != nil {
		fmt.Println("Can not start application:", err)
	}
}

func run(appPath string) error {
	switch runtime.GOOS {
	case "windows": // using powershell to save privileges
		cmd := exec.Command("powershell", "-Command",
			fmt.Sprintf(`Start-Process -FilePath "%s" -Verb RunAs`, appPath),
		)
		cmd.SysProcAttr = nil
		return cmd.Start()

	case "linux":
		cmd := exec.Command(appPath, os.Args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		res := cmd.Start()
		os.Exit(0)
		return res

	default:
		return errors.New("unsupported platform")
	}
}

func getClientVersion(appPath string) (string, error) {
	cmd := exec.Command(appPath, "-version")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
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

func CheckAndUpdate(appPath string, appVersion string) (bool, error) {
	resp, err := http.Get(
		"https://api.github.com/repos/" + RepoOwner + "/" + RepoName + "/releases",
	)
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("github api returned %s", resp.Status)
	}
	defer resp.Body.Close()

	var releases []release
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return false, err
	}

	var commercial *release
	for i := range releases {
		if releases[i].TagName == "commercial" {
			commercial = &releases[i]
			break
		}
	}

	if commercial == nil {
		return false, errors.New(`release with tag "commercial" not found`)
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
		return false, errors.New("can not find the github asset to update")
	}

	remoteVersion, err := extractGitVersion(assetName)
	if err != nil {
		return false, err
	}
	if compareVersions(remoteVersion, appVersion) <= 0 {
		return false, nil
	}
	fmt.Printf("New version found: %s -> %s. Skip update? [y/N]: ", appVersion, remoteVersion)
	var input string
	fmt.Scanln(&input)
	input = strings.TrimSpace(strings.ToLower(input))
	if input != "y" && input != "yes" && input != "д" && input != "да" {
		fmt.Println("Update canceled by user")
		return false, nil
	}

	archiveName := runtime.GOOS + "." + remoteVersion + ".zip"

	tmpZip := filepath.Join(os.TempDir(), archiveName)
	if err := downloadFile(tmpZip, downloadURL); err != nil {
		return false, err
	}

	if err := applyUpdate(appPath, tmpZip); err != nil {
		return false, err
	}

	return true, nil
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

	pw := &progressWriter{
		total: resp.ContentLength,
	}

	fmt.Println()
	reader := io.TeeReader(resp.Body, pw)

	if _, err := io.Copy(out, reader); err != nil {
		return err
	}
	fmt.Println("\n\ndownload complete")
	return nil
}

func applyUpdate(appPath string, zipPath string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		dst := filepath.Join(appPath, f.Name)

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

func extractGitVersion(assetName string) (string, error) {
	base := strings.TrimSuffix(assetName, ".zip")
	parts := strings.Split(base, ".")
	if len(parts) < 2 {
		return "", errors.New("invalid asset name")
	}
	return strings.Join(parts[1:], "."), nil
}
