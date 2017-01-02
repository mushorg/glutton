package logger

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/mushorg/glutton"
	"pkg.re/essentialkaos/z7.v2"
)

type filter interface {
	countFiles() int
	checkStatus(int) bool
	appendFile(int)
}

type directory struct {
	totalFiles      []os.FileInfo
	unCompressed    []string
	path            string
	compressionType string
}

func (d *directory) countFiles() int {
	return len(d.totalFiles)
}

//Error checking: glutton package
func (d *directory) checkStatus(i int) bool {
	if d.totalFiles[i].IsDir() {
		return false
	}
	compressed, err := z7.Check((d.path + d.totalFiles[i].Name()))
	if err != nil {
		log.Println("Not compressed")
	}
	return compressed
}

func (d *directory) appendFile(i int) {
	d.unCompressed = append(d.unCompressed, d.totalFiles[i].Name())
}

func applyFileter(f filter) {
	for i := 0; i < f.countFiles(); i++ {
		if !f.checkStatus(i) {

			f.appendFile(i)
		}
	}
}

func compressFiles(name string) {
	newName := name + ".7z"
	_, err := z7.Add(newName, name)
	glutton.CheckError("CompressFiles() Error: ", err)
	removeFile(name)
}

//Error checking: glutton package
func removeFile(file string) {
	err := os.Remove(file)
	glutton.CheckError("Error in removeFile() files: ", err)
}

func checkForUncompressed() {
	dir := &directory{unCompressed: make([]string, 0), path: "/var/log/glutton/", compressionType: ".7z"}
	f, err := ioutil.ReadDir("/var/log/glutton")
	glutton.CheckError("Error in file_compressor.go checking for uncompressed files", err)
	dir.totalFiles = f
	applyFileter(dir)
	for _, name := range dir.unCompressed {
		if name != filename {
			log.Println("Compressing > ", name)
			compressFiles(dir.path + name)
			log.Println("Compressed", name)
		}
	}
	log.Println("Routine finished")
}
