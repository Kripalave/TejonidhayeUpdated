package TejonidhayeUpdated
import (
	"github.com/go-ldap/ldap"
	"net/http"
	"os"
	"fmt"
	"io"
	"io/ioutil"
	"archive/zip"
	"net"
	"bytes"
	"encoding/binary"
	"errors"
	"syscall"
	"strconv"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"context"
	"crypto/tls"
	"strings"
	"encoding/base64"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"math/big"
	"path/filepath"
	
)

func UnzipFile(src string, dest string) ([]string, error) {

	var filenames []string

	r, err := zip.OpenReader(src)
	if err != nil {
		return filenames, err
	}
	defer r.Close()

	for _, f := range r.File {

		
		fpath := filepath.Join(dest, f.Name)

		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return filenames, fmt.Errorf("%s: illegal file path", fpath)
		}

		filenames = append(filenames, fpath)

		if f.FileInfo().IsDir() {
		
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return filenames, err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return filenames, err
		}

		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}

		_, err = io.Copy(outFile, rc)

		outFile.Close()
		rc.Close()

		if err != nil {
			return filenames, err
		}
	}
	return filenames, nil
}


func RadiusAuthActivation(radiusurl string, radisusername string, radispassword string,radiussecret string)(string,error){
	
	client := radius.Client{
		Retry: -1,
	}
	packet := radius.New(radius.CodeAccessRequest, []byte(radiussecret))
	rfc2865.UserName_SetString(packet, radisusername)
	rfc2865.UserPassword_SetString(packet, radispassword)
	response, err := client.Exchange(context.Background(), packet, radiusurl)
	if err != nil {
		return "RadiusError", err
	}
	return fmt.Sprintf("%v",response.Code),nil
}

func Ldpaauthactivation(ldapurl string,username string,password string,bindstring string)(bool,error){

	bindstring = "cn="+username+","+bindstring

	if strings.Contains(ldapurl, "389"){
		ldapcon, err := ldap.Dial("tcp", ldapurl)
		if err != nil {
			return err == nil, err
		}
		defer ldapcon.Close()
		err = ldapcon.
		Bind(bindstring, password)
		if err != nil {
			return err == nil, err
		}
	}else{
		ldapcon, err := ldap.DialTLS("tcp", ldapurl, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return err == nil, err
		}
		defer ldapcon.Close()
		err = ldapcon.Bind(bindstring, password)
		if err != nil {
			return err == nil, err
		}
	}


	return true,nil
}

func ResponseSendFile(filepath string, filename string, w http.ResponseWriter) {
	Openfile, err := os.Open(filepath)
	if err != nil {
		fmt.Println(err)
	}
	defer Openfile.Close()
	FileHeader := make([]byte, 512)
	Openfile.Read(FileHeader)
	FileContentType := http.DetectContentType(FileHeader)
	FileStat, _ := Openfile.Stat()
	FileSize := strconv.FormatInt(FileStat.Size(), 10)
	w.Header().Set("Content-Disposition", "filename="+filename)
	w.Header().Set("Content-Type", FileContentType)
	w.Header().Set("Content-Length", FileSize)
	w.WriteHeader(200)
	Openfile.Seek(0, 0)
	io.Copy(w, Openfile)

}

func ResponseSendBuffer(filebuffer []byte, filename string, w http.ResponseWriter, contenttypearg string) {

	FileSize := int64(len(filebuffer))
	w.Header().Set("Content-Disposition", "filename="+filename)
	w.Header().Set("Content-Type", contenttypearg)
	w.Header().Set("Content-Length", fmt.Sprintf("%v", FileSize))
	w.WriteHeader(200)
	w.Write(filebuffer)

}

func ResponseSendFileWithType(filepath string, filename string, w http.ResponseWriter,contenttypearg string) {
	Openfile, err := os.Open(filepath)
	if err != nil {
		fmt.Println(err)
	}
	defer Openfile.Close()
	FileHeader := make([]byte, 512)
	Openfile.Read(FileHeader)
	//FileContentType := http.DetectContentType(FileHeader)
	FileStat, _ := Openfile.Stat()
	FileSize := strconv.FormatInt(FileStat.Size(), 10)
	w.Header().Set("Content-Disposition", "filename="+filename)
	w.Header().Set("Content-Type", contenttypearg)
	w.Header().Set("Content-Length", FileSize)
	w.WriteHeader(200)
	Openfile.Seek(0, 0)
	io.Copy(w, Openfile)

}

func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func Checkprocess(filename string) {
	if FileExists(filename) {
		processid, err := ioutil.ReadFile(filename)
		if err == nil {

			pid, err := strconv.Atoi(string(bytes.TrimSpace(processid)))
			if err != nil {
				fmt.Println(err)
			}

			fmt.Println(pid)
			_, err = os.FindProcess(pid)
			if err == nil {
				killErr := syscall.Kill(pid, syscall.Signal(0))
				if killErr == nil {
					os.Exit(0)
				}
			}
		}
	}
	processidfile, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println(err)
	}
	defer processidfile.Close()
	if err != nil {
		fmt.Println(err)
	}
	processidfile.WriteString(fmt.Sprintf("%v", os.Getpid()))

}

func ReadZipFile(zf *zip.File) ([]byte, error) {
	f, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return ioutil.ReadAll(f)
}
func IsEmptyDir(name string) (bool, error) {
	entries, err := ioutil.ReadDir(name)
	if err != nil {
		return false, err
	}
	return len(entries) == 0, err
}

func IsDirEmpty(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()

	// read in ONLY one file
	_, err = f.Readdir(1)

	// and if the file is EOF... well, the dir is empty.
	if err == io.EOF {
		return true, nil
	}
	return false, err
}

func ZipFiles(filename string, files []string) error {

	newZipFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer newZipFile.Close()

	zipWriter := zip.NewWriter(newZipFile)
	defer zipWriter.Close()

	// Add files to zip
	for _, file := range files {
		if err = AddFileToZip(zipWriter, file); err != nil {
			return err
		}
	}
	return nil
}

func AddFileToZip(zipWriter *zip.Writer, filename string) error {

	fileToZip, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fileToZip.Close()

	info, err := fileToZip.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = filename
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(writer, fileToZip)
	return err
}


func RandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}


// func RandomString(n int) string {
// 	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// 	s := make([]rune, n)
// 	for i := range s {
// 		s[i] = letters[mathrand.Int(len(letters))]
// 	}
// 	return string(s)
// }

func DirExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}
func FindIPaddress(cidr string, srcip string, destip string) (bool, error) {

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr == srcip || cidr == destip, nil
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); Inc(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) == 1 {

		return ips[0] == srcip || ips[0] == destip, nil
	} else {

		firstvalue := Ip2Long(ips[1])
		lastvalue := Ip2Long(ips[len(ips)-1])
		srcipvalue := Ip2Long(srcip)
		destipvalue := Ip2Long(destip)
		return (srcipvalue >= firstvalue && srcipvalue <= lastvalue) || (destipvalue >= firstvalue && destipvalue <= lastvalue), nil

	}

}

func Inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
func Ip2Long(ip string) uint32 {
	var long uint32
	binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.BigEndian, &long)
	return long
}
func CheckDomain(domain string) (bool, error) {
	_, err := net.LookupIP(domain)
	if err != nil {
		return false, errors.New("Invalid Domain")
	} else {
		return true, nil
	}
}


func Decrypt(key []byte, cryptoText string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		fmt.Println("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}


func Encrypt(key []byte, text string) string {
	// key := []byte(keyText)
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Println(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
}
