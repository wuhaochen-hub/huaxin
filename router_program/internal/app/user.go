package app

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"router/internal/log"
)

type Config struct {
	User       string `json:"user"`
	Passward   string `json:"passward"`
	IndexValue string `json:indexValue`
}

type User struct {
	congPath     string
	conf         Config
	indexContent []byte
}

func NewUser(path string) *User {
	var user User
	user.congPath = path
	err := user.initConfig()
	if err != nil {
		return &User{
			congPath: path,
			conf: Config{
				User:       "admin",
				Passward:   "admin",
				IndexValue: "",
			},
			indexContent: []byte{},
		}
	}
	return &user
}

func (u *User) initConfig() error {
	// 打开文件
	file, err := os.Open(u.congPath)
	if err != nil {
		log.Slog.Error("Failed to open config file:", "err", err.Error(), "path", u.congPath)
		return err
	}
	defer file.Close()

	// 读取文件内容
	content, err := io.ReadAll(file)
	if err != nil {
		log.Slog.Error("Failed to read config file:", "err", err.Error())
		return err
	}

	err = json.Unmarshal(content, &u.conf)
	if err != nil {
		log.Slog.Error("Failed to unmarshal JSON:", "err", err.Error())
		return err
	}

	hexStr := fmt.Sprintf("%x", u.conf.IndexValue)
	u.indexContent, err = hex.DecodeString(hexStr)
	if err != nil {
		log.Slog.Error("Failed to decode hex", "err", err.Error())
		return err
	}
	return nil
}

func (u *User) ValidPassward(salt string) string {

	one := []byte{0}

	hash := md5.New()
	hash.Write(one)
	hash.Write([]byte(u.conf.Passward))
	hash.Write([]byte(salt))
	hashed := hash.Sum(nil)

	finalHashed := append([]byte{0}, hashed...)
	//return hex.EncodeToString(finalHashed)
	return string(finalHashed)
}

var UserDat = []byte{
	0x5a, 0x00, 0x4d, 0x32, 0x10, 0x00, 0x00, 0xa8, 0x00, 0x00, 0x1c, 0x00,
	0x00, 0x00, 0x0a, 0x00, 0xfe, 0x00, 0x05, 0x00, 0x00, 0x09, 0x00, 0x06,
	0x00, 0x00, 0x09, 0x00, 0x0b, 0x00, 0x00, 0x08, 0xfe, 0xff, 0x07, 0x00,
	0x12, 0x00, 0x00, 0x09, 0x02, 0x01, 0x00, 0xfe, 0x09, 0x01, 0x02, 0x00,
	0x00, 0x09, 0x03, 0x09, 0x00, 0xfe, 0x21, 0x13, 0x73, 0x79, 0x73, 0x74,
	0x65, 0x6d, 0x20, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x20, 0x75,
	0x73, 0x65, 0x72, 0x11, 0x00, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x21,
	0x05, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x62, 0x00, 0x4d, 0x32, 0x10, 0x00,
	0x00, 0xa8, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0xfe, 0x00,
	0x05, 0x00, 0x00, 0x09, 0x00, 0x06, 0x00, 0x00, 0x09, 0x00, 0x1f, 0x00,
	0x00, 0x08, 0x93, 0xf1, 0x1e, 0x5d, 0x0b, 0x00, 0x00, 0x08, 0xfe, 0xff,
	0x07, 0x00, 0x12, 0x00, 0x00, 0x09, 0x02, 0x01, 0x00, 0xfe, 0x09, 0x01,
	0x02, 0x00, 0x00, 0x09, 0x03, 0x09, 0x00, 0xfe, 0x21, 0x13, 0x73, 0x79,
	0x73, 0x74, 0x65, 0x6d, 0x20, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74,
	0x20, 0x75, 0x73, 0x65, 0x72, 0x11, 0x00, 0x00, 0x21, 0x00, 0x01, 0x00,
	0x00, 0x21, 0x05, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x72, 0x00, 0x4d, 0x32,
	0x10, 0x00, 0x00, 0xa8, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x01, 0x0a, 0x00,
	0xfe, 0x00, 0x05, 0x00, 0x00, 0x09, 0x00, 0x06, 0x00, 0x00, 0x09, 0x00,
	0x1f, 0x00, 0x00, 0x08, 0xbb, 0xf2, 0x1e, 0x5d, 0x0b, 0x00, 0x00, 0x08,
	0xfe, 0xff, 0x07, 0x00, 0x12, 0x00, 0x00, 0x09, 0x02, 0x01, 0x00, 0xfe,
	0x09, 0x01, 0x02, 0x00, 0x00, 0x09, 0x03, 0x09, 0x00, 0xfe, 0x21, 0x13,
	0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20, 0x64, 0x65, 0x66, 0x61, 0x75,
	0x6c, 0x74, 0x20, 0x75, 0x73, 0x65, 0x72, 0x11, 0x00, 0x00, 0x21, 0x10,
	0x24, 0xd0, 0xb2, 0x71, 0x28, 0x2e, 0x0e, 0x2d, 0x09, 0xd5, 0xfb, 0x27,
	0xb1, 0x44, 0xec, 0x93, 0x01, 0x00, 0x00, 0x21, 0x05, 0x61, 0x64, 0x6d,
	0x69, 0x6e,
}

var ListData = []byte{
	0x7b, 0x20, 0x63, 0x72, 0x63, 0x3a, 0x20, 0x31, 0x36, 0x34, 0x35, 0x36,
	0x32, 0x38, 0x37, 0x33, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x20,
	0x31, 0x31, 0x34, 0x39, 0x2c, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x20,
	0x22, 0x61, 0x64, 0x76, 0x74, 0x6f, 0x6f, 0x6c, 0x2e, 0x6a, 0x67, 0x22,
	0x2c, 0x20, 0x75, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x3a, 0x20, 0x22, 0x61,
	0x64, 0x76, 0x74, 0x6f, 0x6f, 0x6c, 0x2d, 0x66, 0x63, 0x31, 0x39, 0x33,
	0x32, 0x66, 0x36, 0x38, 0x30, 0x39, 0x65, 0x2e, 0x6a, 0x67, 0x22, 0x2c,
	0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x22, 0x36,
	0x2e, 0x34, 0x31, 0x2e, 0x34, 0x22, 0x20, 0x7d, 0x2c, 0x0a, 0x7b, 0x20,
	0x63, 0x72, 0x63, 0x3a, 0x20, 0x33, 0x36, 0x37, 0x30, 0x36, 0x38, 0x39,
	0x34, 0x38, 0x38, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x20, 0x33,
	0x31, 0x31, 0x39, 0x2c, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x20, 0x22,
	0x64, 0x68, 0x63, 0x70, 0x2e, 0x6a, 0x67, 0x22, 0x2c, 0x20, 0x75, 0x6e,
	0x69, 0x71, 0x75, 0x65, 0x3a, 0x20, 0x22, 0x64, 0x68, 0x63, 0x70, 0x2d,
	0x37, 0x35, 0x66, 0x36, 0x36, 0x39, 0x39, 0x34, 0x62, 0x61, 0x34, 0x31,
	0x2e, 0x6a, 0x67, 0x22, 0x2c, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x3a, 0x20, 0x22, 0x36, 0x2e, 0x34, 0x31, 0x2e, 0x34, 0x22, 0x20,
	0x7d, 0x2c, 0x0a, 0x7b, 0x20, 0x63, 0x72, 0x63, 0x3a, 0x20, 0x31, 0x31,
	0x38, 0x33, 0x37, 0x37, 0x39, 0x38, 0x33, 0x34, 0x2c, 0x20, 0x73, 0x69,
	0x7a, 0x65, 0x3a, 0x20, 0x31, 0x32, 0x34, 0x38, 0x39, 0x2c, 0x20, 0x6e,
	0x61, 0x6d, 0x65, 0x3a, 0x20, 0x22, 0x64, 0x75, 0x64, 0x65, 0x2e, 0x6a,
	0x67, 0x22, 0x2c, 0x20, 0x75, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x3a, 0x20,
	0x22, 0x64, 0x75, 0x64, 0x65, 0x2d, 0x36, 0x35, 0x66, 0x31, 0x38, 0x66,
	0x61, 0x65, 0x64, 0x36, 0x34, 0x39, 0x2e, 0x6a, 0x67, 0x22, 0x2c, 0x20,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x22, 0x36, 0x2e,
	0x34, 0x31, 0x2e, 0x34, 0x22, 0x20, 0x7d, 0x2c, 0x0a, 0x7b, 0x20, 0x63,
	0x72, 0x63, 0x3a, 0x20, 0x34, 0x34, 0x34, 0x37, 0x38, 0x32, 0x37, 0x39,
	0x34, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x20, 0x34, 0x33, 0x33,
	0x2c, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x20, 0x22, 0x67, 0x70, 0x73,
	0x2e, 0x6a, 0x67, 0x22, 0x2c, 0x20, 0x75, 0x6e, 0x69, 0x71, 0x75, 0x65,
	0x3a, 0x20, 0x22, 0x67, 0x70, 0x73, 0x2d, 0x32, 0x31, 0x66, 0x61, 0x38,
	0x31, 0x34, 0x32, 0x33, 0x61, 0x35, 0x65, 0x2e, 0x6a, 0x67, 0x22, 0x2c,
	0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x22, 0x36,
	0x2e, 0x34, 0x31, 0x2e, 0x34, 0x22, 0x20, 0x7d, 0x2c, 0x0a, 0x7b, 0x20,
	0x63, 0x72, 0x63, 0x3a, 0x20, 0x33, 0x35, 0x32, 0x39, 0x32, 0x33, 0x36,
	0x37, 0x37, 0x34, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x20, 0x34,
	0x31, 0x30, 0x39, 0x2c, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x20, 0x22,
	0x68, 0x6f, 0x74, 0x73, 0x70, 0x6f, 0x74, 0x2e, 0x6a, 0x67, 0x22, 0x2c,
	0x20, 0x75, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x3a, 0x20, 0x22, 0x68, 0x6f,
	0x74, 0x73, 0x70, 0x6f, 0x74, 0x2d, 0x63, 0x63, 0x63, 0x33, 0x39, 0x61,
	0x32, 0x38, 0x31, 0x39, 0x62, 0x66, 0x2e, 0x6a, 0x67, 0x22, 0x2c, 0x20,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x22, 0x36, 0x2e,
	0x34, 0x31, 0x2e, 0x34, 0x22, 0x20, 0x7d, 0x2c, 0x0a, 0x7b, 0x20, 0x63,
	0x72, 0x63, 0x3a, 0x20, 0x31, 0x30, 0x39, 0x33, 0x39, 0x37, 0x30, 0x39,
	0x36, 0x35, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x20, 0x32, 0x32,
	0x34, 0x35, 0x31, 0x2c, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x20, 0x22,
	0x69, 0x63, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x6e, 0x67, 0x22, 0x2c, 0x20,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x22, 0x36, 0x2e,
	0x34, 0x31, 0x2e, 0x34, 0x22, 0x20, 0x7d, 0x2c, 0x0a, 0x7b, 0x20, 0x63,
	0x72, 0x63, 0x3a, 0x20, 0x31, 0x36, 0x33, 0x36, 0x33, 0x37, 0x31, 0x39,
	0x31, 0x36, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x20, 0x36, 0x34,
	0x33, 0x30, 0x2c, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x20, 0x22, 0x69,
	0x70, 0x76, 0x36, 0x2e, 0x6a, 0x67, 0x22, 0x2c, 0x20, 0x75, 0x6e, 0x69,
	0x71, 0x75, 0x65, 0x3a, 0x20, 0x22, 0x69, 0x70, 0x76, 0x36, 0x2d, 0x65,
	0x32, 0x62, 0x31, 0x30, 0x66, 0x31, 0x36, 0x66, 0x33, 0x36, 0x61, 0x2e,
	0x6a, 0x67, 0x22, 0x2c, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x3a, 0x20, 0x22, 0x36, 0x2e, 0x34, 0x31, 0x2e, 0x34, 0x22, 0x20, 0x7d,
	0x2c, 0x0a, 0x7b, 0x20, 0x63, 0x72, 0x63, 0x3a, 0x20, 0x31, 0x36, 0x35,
	0x34, 0x36, 0x31, 0x35, 0x33, 0x32, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65,
	0x3a, 0x20, 0x31, 0x34, 0x37, 0x33, 0x2c, 0x20, 0x6e, 0x61, 0x6d, 0x65,
	0x3a, 0x20, 0x22, 0x6b, 0x76, 0x6d, 0x2e, 0x6a, 0x67, 0x22, 0x2c, 0x20,
	0x75, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x3a, 0x20, 0x22, 0x6b, 0x76, 0x6d,
	0x2d, 0x36, 0x65, 0x31, 0x30, 0x32, 0x39, 0x34, 0x37, 0x30, 0x61, 0x34,
	0x34, 0x2e, 0x6a, 0x67, 0x22, 0x2c, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x3a, 0x20, 0x22, 0x36, 0x2e, 0x34, 0x31, 0x2e, 0x34, 0x22,
	0x20, 0x7d, 0x2c, 0x0a, 0x7b, 0x20, 0x63, 0x72, 0x63, 0x3a, 0x20, 0x36,
	0x36, 0x37, 0x38, 0x35, 0x37, 0x32, 0x30, 0x39, 0x2c, 0x20, 0x73, 0x69,
	0x7a, 0x65, 0x3a, 0x20, 0x34, 0x35, 0x35, 0x2c, 0x20, 0x6e, 0x61, 0x6d,
	0x65, 0x3a, 0x20, 0x22, 0x6c, 0x63, 0x64, 0x2e, 0x6a, 0x67, 0x22, 0x2c,
	0x20, 0x75, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x3a, 0x20, 0x22, 0x6c, 0x63,
	0x64, 0x2d, 0x33, 0x30, 0x61, 0x37, 0x34, 0x30, 0x62, 0x66, 0x35, 0x33,
	0x37, 0x35, 0x2e, 0x6a, 0x67, 0x22, 0x2c, 0x20, 0x76, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x22, 0x36, 0x2e, 0x34, 0x31, 0x2e, 0x34,
	0x22, 0x20, 0x7d, 0x2c, 0x0a, 0x7b, 0x20, 0x63, 0x72, 0x63, 0x3a, 0x20,
	0x31, 0x30, 0x32, 0x31, 0x35, 0x31, 0x39, 0x30, 0x33, 0x38, 0x2c, 0x20,
	0x73, 0x69, 0x7a, 0x65, 0x3a, 0x20, 0x33, 0x36, 0x32, 0x38, 0x2c, 0x20,
	0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x20, 0x22, 0x6d, 0x70, 0x6c, 0x73, 0x2e,
	0x6a, 0x67, 0x22, 0x2c, 0x20, 0x75, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x3a,
	0x20, 0x22, 0x6d, 0x70, 0x6c, 0x73, 0x2d, 0x36, 0x63, 0x63, 0x61, 0x36,
	0x36, 0x63, 0x33, 0x66, 0x31, 0x37, 0x30, 0x2e, 0x6a, 0x67, 0x22, 0x2c,
	0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x22, 0x36,
	0x2e, 0x34, 0x31, 0x2e, 0x34, 0x22, 0x20, 0x7d, 0x2c, 0x0a, 0x7b, 0x20,
	0x63, 0x72, 0x63, 0x3a, 0x20, 0x33, 0x33, 0x32, 0x35, 0x34, 0x32, 0x37,
	0x32, 0x30, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x20, 0x34, 0x35,
	0x37, 0x2c, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x20, 0x22, 0x6e, 0x74,
	0x70, 0x2e, 0x6a, 0x67, 0x22, 0x2c, 0x20, 0x75, 0x6e, 0x69, 0x71, 0x75,
	0x65, 0x3a, 0x20, 0x22, 0x6e, 0x74, 0x70, 0x2d, 0x34, 0x31, 0x32, 0x65,
	0x38, 0x30, 0x65, 0x30, 0x36, 0x66, 0x38, 0x38, 0x2e, 0x6a, 0x67, 0x22,
	0x2c, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x22,
	0x36, 0x2e, 0x34, 0x31, 0x2e, 0x34, 0x22, 0x20, 0x7d, 0x2c, 0x0a, 0x7b,
	0x20, 0x63, 0x72, 0x63, 0x3a, 0x20, 0x32, 0x38, 0x37, 0x30, 0x37, 0x36,
	0x32, 0x38, 0x36, 0x33, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a, 0x20,
	0x32, 0x33, 0x34, 0x32, 0x2c, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x20,
	0x22, 0x70, 0x69, 0x6d, 0x2e, 0x6a, 0x67, 0x22, 0x2c, 0x20, 0x75, 0x6e,
	0x69, 0x71, 0x75, 0x65, 0x3a, 0x20, 0x22, 0x70, 0x69, 0x6d, 0x2d, 0x66,
	0x61, 0x63, 0x34, 0x63, 0x65, 0x39, 0x65, 0x64, 0x64, 0x34, 0x34, 0x2e,
	0x6a, 0x67, 0x22, 0x2c, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x3a, 0x20, 0x22, 0x36, 0x2e, 0x34, 0x31, 0x2e, 0x34, 0x22, 0x20, 0x7d,
	0x2c, 0x0a, 0x7b, 0x20, 0x63, 0x72, 0x63, 0x3a, 0x20, 0x32, 0x38, 0x34,
	0x39, 0x34, 0x36, 0x36, 0x35, 0x30, 0x39, 0x2c, 0x20, 0x73, 0x69, 0x7a,
	0x65, 0x3a, 0x20, 0x34, 0x34, 0x30, 0x38, 0x2c, 0x20, 0x6e, 0x61, 0x6d,
	0x65, 0x3a, 0x20, 0x22, 0x70, 0x70, 0x70, 0x2e, 0x6a, 0x67, 0x22, 0x2c,
	0x20, 0x75, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x3a, 0x20, 0x22, 0x70, 0x70,
	0x70, 0x2d, 0x66, 0x36, 0x39, 0x39, 0x30, 0x62, 0x37, 0x37, 0x39, 0x36,
	0x38, 0x32, 0x2e, 0x6a, 0x67, 0x22, 0x2c, 0x20, 0x76, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x22, 0x36, 0x2e, 0x34, 0x31, 0x2e, 0x34,
	0x22, 0x20, 0x7d, 0x2c, 0x0a, 0x7b, 0x20, 0x63, 0x72, 0x63, 0x3a, 0x20,
	0x32, 0x37, 0x34, 0x32, 0x39, 0x35, 0x31, 0x30, 0x35, 0x2c, 0x20, 0x73,
	0x69, 0x7a, 0x65, 0x3a, 0x20, 0x36, 0x33, 0x35, 0x33, 0x33, 0x2c, 0x20,
	0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x20, 0x22, 0x72, 0x6f, 0x74, 0x65, 0x72,
	0x6f, 0x73, 0x2e, 0x6a, 0x67, 0x22, 0x2c, 0x20, 0x75, 0x6e, 0x69, 0x71,
	0x75, 0x65, 0x3a, 0x20, 0x22, 0x72, 0x6f, 0x74, 0x65, 0x72, 0x6f, 0x73,
	0x2d, 0x63, 0x38, 0x36, 0x37, 0x35, 0x33, 0x33, 0x33, 0x61, 0x33, 0x66,
	0x39, 0x2e, 0x6a, 0x67, 0x22, 0x2c, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x3a, 0x20, 0x22, 0x36, 0x2e, 0x34, 0x31, 0x2e, 0x34, 0x22,
	0x20, 0x7d, 0x2c, 0x0a, 0x7b, 0x20, 0x63, 0x72, 0x63, 0x3a, 0x20, 0x32,
	0x39, 0x31, 0x31, 0x30, 0x39, 0x31, 0x38, 0x30, 0x36, 0x2c, 0x20, 0x73,
	0x69, 0x7a, 0x65, 0x3a, 0x20, 0x38, 0x32, 0x34, 0x30, 0x2c, 0x20, 0x6e,
	0x61, 0x6d, 0x65, 0x3a, 0x20, 0x22, 0x72, 0x6f, 0x74, 0x69, 0x6e, 0x67,
	0x34, 0x2e, 0x6a, 0x67, 0x22, 0x2c, 0x20, 0x75, 0x6e, 0x69, 0x71, 0x75,
	0x65, 0x3a, 0x20, 0x22, 0x72, 0x6f, 0x74, 0x69, 0x6e, 0x67, 0x34, 0x2d,
	0x32, 0x63, 0x61, 0x62, 0x65, 0x35, 0x39, 0x31, 0x38, 0x31, 0x65, 0x62,
	0x2e, 0x6a, 0x67, 0x22, 0x2c, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x3a, 0x20, 0x22, 0x36, 0x2e, 0x34, 0x31, 0x2e, 0x34, 0x22, 0x20,
	0x7d, 0x2c, 0x0a, 0x7b, 0x20, 0x63, 0x72, 0x63, 0x3a, 0x20, 0x32, 0x37,
	0x38, 0x34, 0x38, 0x37, 0x30, 0x38, 0x33, 0x37, 0x2c, 0x20, 0x73, 0x69,
	0x7a, 0x65, 0x3a, 0x20, 0x33, 0x34, 0x38, 0x33, 0x2c, 0x20, 0x6e, 0x61,
	0x6d, 0x65, 0x3a, 0x20, 0x22, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x2e,
	0x6a, 0x67, 0x22, 0x2c, 0x20, 0x75, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x3a,
	0x20, 0x22, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x2d, 0x35, 0x38, 0x39,
	0x66, 0x32, 0x65, 0x38, 0x31, 0x34, 0x66, 0x35, 0x34, 0x2e, 0x6a, 0x67,
	0x22, 0x2c, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x20,
	0x22, 0x36, 0x2e, 0x34, 0x31, 0x2e, 0x34, 0x22, 0x20, 0x7d, 0x2c, 0x0a,
	0x7b, 0x20, 0x63, 0x72, 0x63, 0x3a, 0x20, 0x31, 0x36, 0x31, 0x37, 0x39,
	0x33, 0x38, 0x32, 0x33, 0x36, 0x2c, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x3a,
	0x20, 0x37, 0x36, 0x35, 0x2c, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x20,
	0x22, 0x75, 0x70, 0x73, 0x2e, 0x6a, 0x67, 0x22, 0x2c, 0x20, 0x75, 0x6e,
	0x69, 0x71, 0x75, 0x65, 0x3a, 0x20, 0x22, 0x75, 0x70, 0x73, 0x2d, 0x65,
	0x32, 0x39, 0x36, 0x38, 0x33, 0x63, 0x38, 0x64, 0x34, 0x39, 0x32, 0x2e,
	0x6a, 0x67, 0x22, 0x2c, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x3a, 0x20, 0x22, 0x36, 0x2e, 0x34, 0x31, 0x2e, 0x34, 0x22, 0x20, 0x7d,
	0x2c, 0x0a, 0x7b, 0x20, 0x63, 0x72, 0x63, 0x3a, 0x20, 0x32, 0x36, 0x38,
	0x32, 0x39, 0x37, 0x39, 0x36, 0x33, 0x34, 0x2c, 0x20, 0x73, 0x69, 0x7a,
	0x65, 0x3a, 0x20, 0x31, 0x36, 0x31, 0x37, 0x38, 0x2c, 0x20, 0x6e, 0x61,
	0x6d, 0x65, 0x3a, 0x20, 0x22, 0x77, 0x6c, 0x61, 0x6e, 0x36, 0x2e, 0x6a,
	0x67, 0x22, 0x2c, 0x20, 0x75, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x3a, 0x20,
	0x22, 0x77, 0x6c, 0x61, 0x6e, 0x36, 0x2d, 0x38, 0x37, 0x65, 0x64, 0x32,
	0x61, 0x63, 0x66, 0x36, 0x33, 0x65, 0x65, 0x2e, 0x6a, 0x67, 0x22, 0x2c,
	0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x22, 0x36,
	0x2e, 0x34, 0x31, 0x2e, 0x34, 0x22, 0x20, 0x7d, 0x2c, 0x0a,
}
