package app

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"router/internal/log"
	"strings"
)

const (
	k_user_dat_open = iota
	k_list_open
	k_none
	k_init_login
	k_logged_in
	k_close
)

type TransmissionData struct {
	header  []byte
	data    []byte
	wm      *WinboxMessage
	m_state int
	conn    net.Conn
	user    *User
}

// TODO: Implement the constructor for TransmissionData
func NewTransmissionData(connect net.Conn, path string) *TransmissionData {
	return &TransmissionData{
		header:  make([]byte, 0),
		data:    make([]byte, 0),
		wm:      NewWinboxMessage(),
		m_state: k_none,
		conn:    connect,
		user:    NewUser(path),
	}
}

func (t *TransmissionData) validateHeader() uint32 {
	shortLength := uint8(t.header[0])
	longLength := binary.BigEndian.Uint16(t.header[2:4])
	log.Slog.Debug("传输数据长度", "shortLength", shortLength, "longLength", longLength)
	if shortLength == 0xff {
		return uint32(longLength)
	}
	if uint16(shortLength-2) != longLength {
		return 0
	}

	return uint32(longLength)
}

func (t *TransmissionData) HandlerProcess() bool {

	t.header = make([]byte, 4) // 创建一个缓冲区来存储读取的数据
	_, err := t.conn.Read(t.header)
	if err != nil {
		log.Slog.Error("Failed to read data:", "err", err.Error())
		return false
	}

	msg_size := t.validateHeader()
	if msg_size != 0 {
		t.data = make([]byte, msg_size)
		_, err := t.conn.Read(t.data)
		if err != nil {
			log.Slog.Error("Failed to read data", "err", err.Error())
			return true
		}
		t.wm.parseBinary(t.data)
		log.Slog.Debug("read data pares to wm", "wm", t.wm)
		t.handleRequest()
	}
	return true
}

func (t *TransmissionData) handleRequest() {
	sys_to := t.wm.getU32Array(0xff0001)
	if len(sys_to) == 0 {
		log.Slog.Warn("Received a message with no system to array.")
		return
	}

	log.Slog.Info(t.wm.SerializeToJson())

	if len(sys_to) == 2 && sys_to[0] == 2 && sys_to[1] == 2 {
		t.doMproxyFileRequest()
		return
	} else if len(sys_to) == 2 && sys_to[0] == 13 && sys_to[1] == 4 {
		t.doLoginRequest()
		return
	} else if t.m_state == k_logged_in {
		return
	}

	t.m_state = k_close
	t.sendError()
}

func (t *TransmissionData) doMproxyFileRequest() {
	cmd := t.wm.getU32(0x00ff0007)
	log.Slog.Debug("doMproxyFileRequest", "cmd", cmd)
	if cmd == 7 { // open for reading no-auth
		open_response := NewWinboxMessage()

		// find the path the user wants to read.
		path := t.wm.getString(1)

		log.Slog.Debug("doMproxyFileRequest", "path", path)
		// handle different files differently
		if strings.Contains(path, "index") {
			open_response.addU32(2, uint32(len(t.user.indexContent))) // sizeof user.dat
			t.m_state = k_user_dat_open
		} else if path == "list" {
			// Respond with the sizeof our list file
			open_response.addU32(2, 1798)
			t.m_state = k_list_open
		} else {
			t.sendError()
			return
		}

		// {u2:188,ufe0001:1,uff0003:2,uff0006:1,Uff0001:[],Uff0002:[2,2]}
		open_response.addU32(0xfe0001, 1) // session id
		if t.wm.getU32(0xff0003) != 0 {
			open_response.addU32(0xff0003, t.wm.getU32(0xff0003)) // seq
		}
		open_response.addU32Array(0xff0002, t.wm.getU32Array(0xff0002)) // from
		open_response.addU32Array(0xff0001, []uint32{})                 // to
		open_response.addU32(0xff0006, t.wm.getU32(0xff0006))
		t.sendMessagee(open_response)
	} else if cmd == 4 { // read file
		//conn.m_log.log(k_info, conn.m_ip, conn.m_port, "Request for file contents")

		file_contents := NewWinboxMessage()

		switch t.m_state {
		case k_user_dat_open:
			file_contents.addRaw(3, string(t.user.indexContent[:len(t.user.indexContent)]))
		case k_list_open:
			file_contents.addRaw(3, string(ListData[:1798]))
		default:
			t.sendError()
			t.m_state = k_close
			return
		}

		t.m_state = k_none
		file_contents.addU32(0xfe0001, 1) // session id
		if t.wm.getU32(0xff0003) != 0 {
			file_contents.addU32(0xff0003, t.wm.getU32(0xff0003)) // seq
		}
		file_contents.addU32Array(0xff0002, t.wm.getU32Array(0xff0002)) // from
		file_contents.addU32Array(0xff0001, []uint32{})                 // to
		file_contents.addU32(0xff0006, t.wm.getU32(0xff0006))
		t.sendMessagee(file_contents)
	} else if cmd == 5 { // cancel
		// {uff0003:2,uff0006:2,Uff0001:[],Uff0002:[2,2]}
		t.m_state = k_none
		cancel := NewWinboxMessage()
		cancel.addU32(0xfe0001, 1) // session id
		if t.wm.getU32(0xff0003) != 0 {
			cancel.addU32(0xff0003, t.wm.getU32(0xff0003)) // seq
		}
		cancel.addU32Array(0xff0002, t.wm.getU32Array(0xff0002)) // from
		cancel.addU32Array(0xff0001, []uint32{})                 // to
		cancel.addU32(0xff0006, t.wm.getU32(0xff0006))
		t.sendMessagee(cancel)
	}
}

func (t *TransmissionData) doLoginRequest() {
	cmd := t.wm.getU32(0xff0007)
	log.Slog.Debug("doLoginRequest", "cmd", cmd)
	if cmd == 4 { // hash request
		t.m_state = k_init_login

		hash_response := NewWinboxMessage()
		hash_response.addU32(0xff0003, t.wm.getU32(0xff0003))           // seq
		hash_response.addU32Array(0xff0002, t.wm.getU32Array(0xff0001)) // from
		hash_response.addU32Array(0xff0001, t.wm.getU32Array(0xff0002)) // to
		hash_response.addU32(0xff0006, t.wm.getU32(0xff0003))

		salt := make([]byte, 16)
		_, err := rand.Read(salt)
		if err != nil {
			log.Slog.Error("generate salt", "err", err.Error())
		}
		hash_response.addRaw(9, string(salt))
		t.sendMessagee(hash_response)
	} else if cmd == 1 { // login
		//conn.m_log.log(k_info, conn.m_ip, conn.m_port, "Login request.")
		if !t.loginValid() {
			t.sendError()
			return
		}
		t.m_state = k_logged_in

		success := NewWinboxMessage()
		success.addU32(0xfe0001, 1)                               // session id
		success.addU32(0xff0003, t.wm.getU32(0xff0003))           // seq
		success.addU32Array(0xff0002, t.wm.getU32Array(0xff0001)) // from
		success.addU32Array(0xff0001, t.wm.getU32Array(0xff0002)) // to
		success.addU32(0xff0006, t.wm.getU32(0xff0003))
		success.addBoolean(0x13, false)
		success.addU32(0xb, 52486)
		success.addU32(0xf, 0)
		success.addU32(0x10, 4)
		success.addString(0x11, "mips")
		success.addString(0x12, "952-hb")
		success.addString(0x14, "")
		success.addString(0x15, "RB952Ui-5ac2nD")
		success.addString(0x16, "3.11")
		success.addString(0x17, "RB700")
		success.addString(0x18, "default")
		t.sendMessagee(success)
	}
}

func (t *TransmissionData) loginValid() bool {
	salt := t.wm.getRaw(9)
	log.Slog.Debug("user and passward valid", "input", t.wm.getRaw(10), "real", t.user.ValidPassward(salt))
	return t.wm.getRaw(10) == t.user.ValidPassward(salt)
}

func (t *TransmissionData) sendMessagee(pMsg *WinboxMessage) bool {
	serialized := pMsg.SerializeToBinary()

	// each message starts with M2 (message format 2) identifier
	message := append([]byte("M2"), serialized...)

	if len(message) > 0xffff {
		fmt.Println("Winbox message oversized")
		return false
	}

	msgSize := []byte{
		byte(len(message) >> 8),   // 0: upper byte
		byte(len(message) & 0xff), // 1: lower byte
	}

	var request bytes.Buffer

	if len(message) < 0xfe {
		request.WriteByte(byte(msgSize[1] + 2))
		request.WriteByte(0x01)
		request.Write(msgSize)
		request.Write(message)
	} else {
		request.WriteByte(0xff)
		request.WriteByte(0x01)
		request.Write(msgSize)
		request.Write(message[:0xfd]) // 0xff-2, because we write 2 bytes above
		for i := 0xfd; i < len(message); i += 0xff {
			var remain byte
			if len(message)-i > 0xff {
				remain = 0xff
			} else {
				remain = byte(len(message) - i)
			}
			request.WriteByte(remain)
			request.WriteByte(0xff)
			request.Write(message[i : i+int(remain)])
		}
	}

	_, err := t.conn.Write(request.Bytes())
	if err != nil {
		log.Slog.Error("Error writing response", "err", err.Error())
		return false
	}

	log.Slog.Info("sendmessage", "value", pMsg.SerializeToJson())
	return true
}

func (t *TransmissionData) sendError() {
	// respond with an error message and exit
	// {uff0003:2,uff0004:2,uff0006:1,uff0008:16646153,Uff0001:[],Uff0002:[2,2]}
	eWM := NewWinboxMessage()
	eWM.addU32Array(0xff0002, t.wm.getU32Array(0xff0001)) // from
	eWM.addU32Array(0xff0001, t.wm.getU32Array(0xff0002)) // to
	eWM.addU32(0xff0008, 16646153)
	eWM.addU32(0xff0006, t.wm.getU32(0xff0006))
	t.sendMessagee(eWM)
}
