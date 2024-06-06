package app

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	kBool         = 0
	kShortLength  = 0x01000000
	kU32          = 0x08000000
	kU64          = 0x10000000
	kIp6          = 0x18000000
	kString       = 0x20000000
	kMessage      = 0x28000000
	kRaw          = 0x30000000
	kBoolArray    = 0x80000000
	kU32Array     = 0x88000000
	kU64Array     = 0x90000000
	kIp6Array     = 0x98000000
	kStringArray  = 0xa0000000
	kMessageArray = 0xa8000000
	kRawArray     = 0xb0000000
)

const (
	kSysTo         = 0x00ff0001
	kFrom          = 0x00ff0002
	kReplyExpected = 0x00ff0005
	kRequestId     = 0x00ff0006
	kCommand       = 0x00ff0007
	kErrorCode     = 0x00ff0008
	kErrorString   = 0x00ff0009
	kSessionId     = 0x00fe0001
)

const (
	kNotImplemented   = 0x00fe0002
	kNotImplementedv2 = 0x00fe0003
	kObjNonexistant   = 0x00fe0004
	kNotPermitted     = 0x00fe0009
	kTimeout          = 0x00fe000d
	kObjNonexistant2  = 0x00fe0011
	kBusy             = 0x00fe0012
)

type WinboxMessage struct {
	bools       map[uint32]bool
	u32s        map[uint32]uint32
	u64s        map[uint32]uint64
	ip6s        map[uint32][16]byte
	strings     map[uint32]string
	msgs        map[uint32]WinboxMessage
	raw         map[uint32]string
	boolArray   map[uint32][]bool
	u32Array    map[uint32][]uint32
	u64Array    map[uint32][]uint64
	ip6Array    map[uint32][][16]byte
	stringArray map[uint32][]string
	msgArray    map[uint32][]WinboxMessage
	rawArray    map[uint32][]string
}

func NewWinboxMessage() *WinboxMessage {
	return &WinboxMessage{
		bools:       make(map[uint32]bool),
		u32s:        make(map[uint32]uint32),
		u64s:        make(map[uint32]uint64),
		ip6s:        make(map[uint32][16]byte),
		strings:     make(map[uint32]string),
		msgs:        make(map[uint32]WinboxMessage),
		raw:         make(map[uint32]string),
		boolArray:   make(map[uint32][]bool),
		u32Array:    make(map[uint32][]uint32),
		u64Array:    make(map[uint32][]uint64),
		ip6Array:    make(map[uint32][][16]byte),
		stringArray: make(map[uint32][]string),
		msgArray:    make(map[uint32][]WinboxMessage),
		rawArray:    make(map[uint32][]string),
	}
}

func (w *WinboxMessage) Reset() {
	w.bools = make(map[uint32]bool)
	w.u32s = make(map[uint32]uint32)
	w.u64s = make(map[uint32]uint64)
	w.ip6s = make(map[uint32][16]byte)
	w.strings = make(map[uint32]string)
	w.msgs = make(map[uint32]WinboxMessage)
	w.raw = make(map[uint32]string)
	w.boolArray = make(map[uint32][]bool)
	w.u32Array = make(map[uint32][]uint32)
	w.u64Array = make(map[uint32][]uint64)
	w.ip6Array = make(map[uint32][][16]byte)
	w.stringArray = make(map[uint32][]string)
	w.msgArray = make(map[uint32][]WinboxMessage)
	w.rawArray = make(map[uint32][]string)
}

func (w *WinboxMessage) SerializeToBinary() string {
	var returnVal string

	for k, v := range w.bools {
		command := make([]byte, 4)
		typeVal := k
		if v {
			typeVal |= kShortLength
		}
		binary.LittleEndian.PutUint32(command, typeVal)
		returnVal += string(command)
	}

	for k, v := range w.u32s {
		var command []byte
		typeVal := kU32 | k
		value := v

		if value > 255 {
			// two byte length
			command = make([]byte, 8)
			binary.LittleEndian.PutUint32(command, typeVal)
			binary.LittleEndian.PutUint32(command[4:], value)
		} else {
			// one byte length
			typeVal |= kShortLength
			command = make([]byte, 5)
			binary.LittleEndian.PutUint32(command, typeVal)
			command[4] = byte(value & 0xff)
		}

		returnVal += string(command)
	}

	for k, v := range w.u64s {
		command := make([]byte, 12)
		typeVal := kU64 | k
		value := v

		binary.LittleEndian.PutUint32(command, typeVal)
		binary.LittleEndian.PutUint64(command[4:], value)

		returnVal += string(command)
	}

	for k, v := range w.ip6s {
		command := make([]byte, 20)
		typeVal := kIp6 | k

		binary.LittleEndian.PutUint32(command, typeVal)
		copy(command[4:], v[:])

		returnVal += string(command)
	}

	for k, v := range w.strings {
		typeVal := kString | k
		command := make([]byte, 5)

		if len(v) > 255 {
			// two byte length
			length := len(v)
			binary.LittleEndian.PutUint32(command, typeVal)
			binary.LittleEndian.PutUint16(command[4:], uint16(length))
			command = append(command, []byte(v)...)
		} else {
			// one byte length
			typeVal |= kShortLength
			length := len(v)
			binary.LittleEndian.PutUint32(command, typeVal)
			command[4] = byte(length)
			command = append(command, []byte(v)...)
		}

		returnVal += string(command)
	}

	for k, v := range w.msgs {
		typeVal := kMessage | k
		command := make([]byte, 5)
		serialized := "M2" + v.SerializeToBinary()

		if len(serialized) > 255 {
			// two byte length
			length := len(serialized)
			binary.LittleEndian.PutUint32(command, typeVal)
			binary.LittleEndian.PutUint16(command[4:], uint16(length))
			command = append(command, []byte(serialized)...)
		} else {
			// one byte length
			typeVal |= kShortLength
			length := len(serialized)
			binary.LittleEndian.PutUint32(command, typeVal)
			command[4] = byte(length)
			command = append(command, []byte(serialized)...)
		}

		returnVal += string(command)
	}

	for k, v := range w.raw {
		var command bytes.Buffer
		var typeVal uint32 = kRaw | k

		if len(v) > 255 {
			// two byte length
			var length uint16 = uint16(len(v))
			binary.Write(&command, binary.LittleEndian, typeVal)
			binary.Write(&command, binary.LittleEndian, length)
			command.WriteString(v)
		} else {
			// one byte length
			typeVal |= kShortLength
			var length uint8 = uint8(len(v))
			binary.Write(&command, binary.LittleEndian, typeVal)
			command.WriteByte(length)
			command.WriteString(v)
		}
		returnVal += command.String()
	}

	for k, v := range w.boolArray {
		typeVal := kBoolArray | k
		arraySize := len(v)
		var command bytes.Buffer
		binary.Write(&command, binary.LittleEndian, typeVal)
		binary.Write(&command, binary.LittleEndian, arraySize)
		for _, value := range v {
			binary.Write(&command, binary.LittleEndian, value)
		}

		returnVal += command.String()
	}

	for k, v := range w.u32Array {
		typeVal := kU32Array | k
		arraySize := len(v)
		command := make([]byte, 6)

		binary.LittleEndian.PutUint32(command, typeVal)
		binary.LittleEndian.PutUint16(command[4:], uint16(arraySize))
		for i := 0; i < arraySize; i++ {
			command = append(command, byte(v[i]))
		}

		returnVal += string(command)
	}

	for k, v := range w.u64Array {
		typeVal := kU64Array | k
		arraySize := len(v)
		command := make([]byte, 6)

		binary.LittleEndian.PutUint32(command, typeVal)
		binary.LittleEndian.PutUint16(command[4:], uint16(arraySize))
		for i := 0; i < arraySize; i++ {
			binary.LittleEndian.PutUint64(command[i+6:], v[i])
		}

		returnVal += string(command)
	}

	for k, v := range w.ip6Array {
		typeVal := kIp6Array | k
		arraySize := len(v)
		command := make([]byte, 6)

		binary.LittleEndian.PutUint32(command, typeVal)
		binary.LittleEndian.PutUint16(command[4:], uint16(arraySize))
		for i := 0; i < arraySize; i++ {
			copy(command[i+6:], v[i][:])
		}

		returnVal += string(command)
	}

	for k, v := range w.stringArray {
		typeVal := kStringArray | k
		arraySize := len(v)
		command := make([]byte, 6)

		binary.LittleEndian.PutUint32(command, typeVal)
		binary.LittleEndian.PutUint16(command[4:], uint16(arraySize))

		for i := 0; i < arraySize; i++ {
			length := len(v[i])
			command = append(command, make([]byte, 2)...)
			binary.LittleEndian.PutUint16(command[len(command)-2:], uint16(length))
			command = append(command, []byte(v[i])...)
		}

		returnVal += string(command)
	}

	for k, v := range w.msgArray {
		typeVal := kMessageArray | k
		arraySize := len(v)
		command := make([]byte, 6)

		binary.LittleEndian.PutUint32(command, typeVal)
		binary.LittleEndian.PutUint16(command[4:], uint16(arraySize))

		for i := 0; i < arraySize; i++ {
			tempMsg := v[i]
			tempString := tempMsg.SerializeToBinary()

			length := len(tempString)
			command = append(command, make([]byte, 2)...)
			binary.LittleEndian.PutUint16(command[len(command)-2:], uint16(length))
			command = append(command, []byte(tempString)...)
		}

		returnVal += string(command)
	}

	for k, v := range w.rawArray {
		typeVal := kRawArray | k
		arraySize := len(v)
		command := make([]byte, 6)

		binary.LittleEndian.PutUint32(command, typeVal)
		binary.LittleEndian.PutUint16(command[4:], uint16(arraySize))

		for i := 0; i < arraySize; i++ {
			length := len(v[i])
			command = append(command, make([]byte, 2)...)
			binary.LittleEndian.PutUint16(command[len(command)-2:], uint16(length))
			command = append(command, []byte(v[i])...)
		}

		returnVal += string(command)
	}

	return returnVal
}

func (w *WinboxMessage) SerializeToJson() string {
	returnVal := "{"

	first := true
	for k, v := range w.bools {
		if !first {
			returnVal += ","
		} else {
			first = false
		}
		returnVal += fmt.Sprintf("b%x:%v", k, v)
	}

	for k, v := range w.u32s {
		if !first {
			returnVal += ","
		} else {
			first = false
		}
		returnVal += fmt.Sprintf("u%x:%d", k, v)
	}

	for k, v := range w.u64s {
		if !first {
			returnVal += ","
		} else {
			first = false
		}
		returnVal += fmt.Sprintf("q%x:%d", k, v)
	}

	for k, v := range w.strings {
		if !first {
			returnVal += ","
		} else {
			first = false
		}
		returnVal += fmt.Sprintf("s%x:'%s'", k, v)
	}

	for k, v := range w.raw {
		if !first {
			returnVal += ","
		} else {
			first = false
		}
		returnVal += fmt.Sprintf("r%x:[", k)

		arrayFirst := true
		for i := 0; i < len(v); i++ {
			if !arrayFirst {
				returnVal += ","
			} else {
				arrayFirst = false
			}
			returnVal += fmt.Sprintf("%d", int(v[i])&0xff)
		}

		returnVal += "]"
	}

	for k, v := range w.msgs {
		if !first {
			returnVal += ","
		} else {
			first = false
		}
		returnVal += fmt.Sprintf("m%x:%s", k, v.SerializeToJson())
	}

	for k, v := range w.boolArray {
		if !first {
			returnVal += ","
		} else {
			first = false
		}
		returnVal += fmt.Sprintf("B%x:[", k)

		arrayFirst := true
		for i := 0; i < len(v); i++ {
			if !arrayFirst {
				returnVal += ","
			} else {
				arrayFirst = false
			}
			returnVal += fmt.Sprintf("%v", v[i])
		}

		returnVal += "]"
	}

	for k, v := range w.u32Array {
		if !first {
			returnVal += ","
		} else {
			first = false
		}
		returnVal += fmt.Sprintf("U%x:[", k)

		arrayFirst := true
		for i := 0; i < len(v); i++ {
			if !arrayFirst {
				returnVal += ","
			} else {
				arrayFirst = false
			}
			returnVal += fmt.Sprintf("%d", v[i])
		}

		returnVal += "]"
	}

	for k, v := range w.u64Array {
		if !first {
			returnVal += ","
		} else {
			first = false
		}
		returnVal += fmt.Sprintf("Q%x:[", k)

		arrayFirst := true
		for i := 0; i < len(v); i++ {
			if !arrayFirst {
				returnVal += ","
			} else {
				arrayFirst = false
			}
			returnVal += fmt.Sprintf("%d", v[i])
		}

		returnVal += "]"
	}

	for k, v := range w.stringArray {
		if !first {
			returnVal += ","
		} else {
			first = false
		}
		returnVal += fmt.Sprintf("S%x:[", k)

		arrayFirst := true
		for i := 0; i < len(v); i++ {
			if !arrayFirst {
				returnVal += ","
			} else {
				arrayFirst = false
			}
			returnVal += fmt.Sprintf("'%s'", v[i])
		}

		returnVal += "]"
	}

	for k, v := range w.msgArray {
		if !first {
			returnVal += ","
		} else {
			first = false
		}
		returnVal += fmt.Sprintf("M%x:[", k)

		arrayFirst := true
		for i := 0; i < len(v); i++ {
			if !arrayFirst {
				returnVal += ","
			} else {
				arrayFirst = false
			}
			returnVal += v[i].SerializeToJson()
		}

		returnVal += "]"
	}

	returnVal += "}"
	return returnVal
}

func (msg *WinboxMessage) parseBinary(pInput []byte) bool {
	input := make([]byte, len(pInput))
	copy(input, pInput)

	if len(input) > 2 && bytes.Compare(input[:2], []byte("M2")) == 0 {
		input = input[2:]
	}

	for len(input) >= 4 {
		typeName := binary.LittleEndian.Uint32(input[:4])
		typeVal := typeName & 0xf8000000
		name := typeName & 0x00ffffff
		input = input[4:]

		switch typeVal {
		case kBool:
			msg.bools[name] = (typeName & kShortLength) != 0
		case kU32:
			if typeName&kShortLength != 0 && len(input) > 0 {
				msg.u32s[name] = uint32(input[0] & 0xff)
				input = input[1:]
			} else if len(input) >= 4 {
				value := binary.LittleEndian.Uint32(input[:4])
				msg.u32s[name] = value
				input = input[4:]
			}
		case kU64:
			if len(input) >= 8 {
				value := binary.LittleEndian.Uint64(input[:8])
				msg.u64s[name] = value
				input = input[8:]
			}
		case kIp6:
			if len(input) >= 16 {
				var value [16]byte
				copy(value[:], input[:16])
				msg.ip6s[name] = value
				input = input[16:]
			}
		case kRaw, kString:
			if len(input) >= 2 {
				length := uint16(input[0] & 0xff)
				if typeName&kShortLength != 0 {
					input = input[1:]
				} else {
					length = binary.LittleEndian.Uint16(input[:2])
					input = input[2:]
				}

				if len(input) >= int(length) {
					value := string(input[:length])
					if typeVal == kRaw {
						msg.raw[name] = value
					} else {
						msg.strings[name] = value
					}
					input = input[length:]
				} else {
					if typeVal == kRaw {
						msg.raw[name] = string(input)
					} else {
						msg.strings[name] = string(input)
					}
					input = nil
				}
			}
		case kMessage:
			if len(input) >= 2 {
				length := uint16(input[0] & 0xff)
				if typeName&kShortLength != 0 {
					input = input[1:]
				} else {
					length = binary.LittleEndian.Uint16(input[:2])
					input = input[2:]
				}

				if len(input) >= int(length) {
					value := string(input[:length])
					if len(value) > 2 && value[0] == 'M' && value[1] == '2' {
						value = value[2:]
						temp := WinboxMessage{}
						temp.parseBinary([]byte(value))
						msg.msgs[name] = temp
						input = input[length:]
					}
				} else if len(input) > 2 && input[0] == 'M' && input[1] == '2' {
					input = input[2:]
					temp := WinboxMessage{}
					temp.parseBinary(input)
					msg.msgs[name] = temp
					input = nil
				}
			}
		case kBoolArray:
			if len(input) >= 2 {
				entries := binary.LittleEndian.Uint16(input[:2])
				input = input[2:]

				bools := make([]bool, entries)
				if len(input) >= int(entries) {
					for i := 0; i < int(entries); i++ {
						bools[i] = input[i] == 1
					}
					input = input[entries:]
				}
				msg.boolArray[name] = bools
			}
		case kU32Array:
			if len(input) >= 2 {
				entries := binary.LittleEndian.Uint16(input[:2])
				input = input[2:]

				u32s := make([]uint32, entries)
				if len(input) >= int(entries*4) {
					for i := 0; i < int(entries); i++ {
						u32s[i] = binary.LittleEndian.Uint32(input[i*4 : (i+1)*4])
					}
					input = input[entries*4:]
				}
				msg.u32Array[name] = u32s
			}
		case kU64Array:
			if len(input) >= 2 {
				entries := binary.LittleEndian.Uint16(input[:2])
				input = input[2:]

				u64s := make([]uint64, entries)
				if len(input) >= int(entries*8) {
					for i := 0; i < int(entries); i++ {
						u64s[i] = binary.LittleEndian.Uint64(input[i*8 : (i+1)*8])
					}
					input = input[entries*8:]
				}
				msg.u64Array[name] = u64s
			}
		case kIp6Array:
			if len(input) >= 2 {
				entries := binary.LittleEndian.Uint16(input[:2])
				input = input[2:]

				ip6s := make([][16]byte, entries)
				if len(input) >= int(entries*16) {
					for i := 0; i < int(entries); i++ {
						copy(ip6s[i][:], input[i*16:(i+1)*16])
					}
					input = input[entries*16:]
				}
				msg.ip6Array[name] = ip6s
			}
		case kRawArray, kStringArray:
			if len(input) >= 2 {
				entries := binary.LittleEndian.Uint16(input[:2])
				input = input[2:]

				strings := make([]string, entries)
				if len(input) >= int(entries*3) {
					consumed := 0
					for i := 0; i < int(entries) && consumed < len(input); i++ {
						if consumed+2 < len(input) {
							length := binary.LittleEndian.Uint16(input[consumed : consumed+2])
							consumed += 2

							if consumed+int(length) <= len(input) {
								tempString := string(input[consumed : consumed+int(length)])
								strings[i] = tempString
								consumed += int(length)
							}
						}
					}
					input = input[consumed:]
				}
				if typeVal == kRawArray {
					msg.rawArray[name] = strings
				} else {
					msg.stringArray[name] = strings
				}
			}
		case kMessageArray:
			if len(input) >= 2 {
				entries := binary.LittleEndian.Uint16(input[:2])
				input = input[2:]

				msgs := make([]WinboxMessage, entries)
				if len(input) >= int(entries*6) {
					consumed := 0
					for i := 0; i < int(entries) && consumed < len(input); i++ {
						if consumed+2 < len(input) {
							length := binary.LittleEndian.Uint16(input[consumed : consumed+2])
							consumed += 2

							if consumed+int(length) <= len(input) {
								tempString := string(input[consumed : consumed+int(length)])
								if len(tempString) > 2 && tempString[0] == 'M' && tempString[1] == '2' {
									tempString = tempString[2:]
									tempMessage := WinboxMessage{}
									tempMessage.parseBinary([]byte(tempString))
									msgs[i] = tempMessage
									consumed += int(length)
								}
							}
						}
					}
					input = input[consumed:]
				}
				msg.msgArray[name] = msgs
			}
		default:
			//fmt.Printf("Parsing error: %x\n", typeVal&0xff)
		}
	}
	return true
}

func (w *WinboxMessage) parseJSON(pInput string) bool {
	if len(pInput) <= 1 || pInput[0] != '{' {
		return false
	}

	input := pInput[1:]

	for len(input) >= 4 {
		typeChar := input[0]
		input = input[1:]

		variableEnd := strings.Index(input, ":")
		if variableEnd == -1 {
			return false
		}

		variableString := input[:variableEnd]
		input = input[variableEnd+1:]

		variable, err := strconv.ParseUint(variableString, 16, 32)
		if err != nil {
			return false
		}

		switch typeChar {
		case 'b':
			if len(input) > 1 {
				if input[0] == '1' {
					w.bools[uint32(variable)] = true
				} else if input[0] == '0' {
					w.bools[uint32(variable)] = false
				} else {
					return false
				}
				input = input[1:]
			}
		case 'u':
			captureInt := regexp.MustCompile(`^([0-9]+)`)
			match := captureInt.FindStringSubmatch(input)
			if match == nil {
				return false
			}
			valueString := match[0]
			input = input[len(valueString):]

			value, err := strconv.ParseUint(valueString, 10, 32)
			if err != nil {
				return false
			}
			w.u32s[uint32(variable)] = uint32(value)
		case 'q':
			captureInt := regexp.MustCompile(`^([0-9]+)`)
			match := captureInt.FindStringSubmatch(input)
			if match == nil {
				return false
			}
			valueString := match[0]
			input = input[len(valueString):]

			value, err := strconv.ParseUint(valueString, 10, 64)
			if err != nil {
				return false
			}
			w.u64s[uint32(variable)] = value
		case 'r':
			captureString := regexp.MustCompile(`^\[([,0-9]+)\]`)
			match := captureString.FindStringSubmatch(input)
			if match == nil {
				return false
			}
			fullMatch := match[0]
			valueString := match[1]
			input = input[len(fullMatch):]

			rawChars := strings.Split(valueString, ",")

			var result string
			for _, rawChar := range rawChars {
				value, err := strconv.ParseUint(rawChar, 10, 8)
				if err != nil {
					return false
				}
				result += string(value)
			}

			w.raw[uint32(variable)] = result
		case 's':
			captureString := regexp.MustCompile(`^'(.+?)'(?:,|})`)
			match := captureString.FindStringSubmatch(input)
			if match == nil {
				return false
			}
			fullMatch := match[0]
			valueString := match[1]
			input = input[len(fullMatch)-1:]
			w.strings[uint32(variable)] = valueString
		case 'm':
			captureMessage := regexp.MustCompile(`^(\{.+?\})(?:,|})`)
			match := captureMessage.FindStringSubmatch(input)
			if match == nil {
				return false
			}
			fullMatch := match[0]
			valueString := match[1]
			input = input[len(fullMatch)-1:]

			tempMsg := WinboxMessage{}
			if !tempMsg.parseJSON(valueString) {
				return false
			}
			w.msgs[uint32(variable)] = tempMsg
		case 'B':
			captureMessage := regexp.MustCompile(`^\[([0-1,]+)\](?:,|})`)
			match := captureMessage.FindStringSubmatch(input)
			if match == nil {
				return false
			}
			fullMatch := match[0]
			valueString := match[1]
			input = input[len(fullMatch)-1:]

			boolsStrings := strings.Split(valueString, ",")

			var bools []bool
			for _, boolString := range boolsStrings {
				boolValue, err := strconv.ParseBool(boolString)
				if err != nil {
					return false
				}
				bools = append(bools, boolValue)
			}
			w.boolArray[uint32(variable)] = bools
		case 'U':
			captureMessage := regexp.MustCompile(`^\[([0-9,]+)\](?:,|})`)
			match := captureMessage.FindStringSubmatch(input)
			if match == nil {
				return false
			}
			fullMatch := match[0]
			valueString := match[1]
			input = input[len(fullMatch)-1:]

			u32Strings := strings.Split(valueString, ",")

			var u32s []uint32
			for _, u32String := range u32Strings {
				value, err := strconv.ParseUint(u32String, 10, 32)
				if err != nil {
					return false
				}
				u32s = append(u32s, uint32(value))
			}
			w.u32Array[uint32(variable)] = u32s
		case 'Q':
			captureMessage := regexp.MustCompile(`^\[([0-9,]+)\](?:,|})`)
			match := captureMessage.FindStringSubmatch(input)
			if match == nil {
				return false
			}
			fullMatch := match[0]
			valueString := match[1]
			input = input[len(fullMatch)-1:]

			u64Strings := strings.Split(valueString, ",")

			var u64s []uint64
			for _, u64String := range u64Strings {
				value, err := strconv.ParseUint(u64String, 10, 64)
				if err != nil {
					return false
				}
				u64s = append(u64s, value)
			}
			w.u64Array[uint32(variable)] = u64s
		case 'S':
			captureMessage := regexp.MustCompile(`^\[(.+?)\](?:,|})`)
			match := captureMessage.FindStringSubmatch(input)
			if match == nil {
				return false
			}

			fullMatch := match[0]
			valueString := match[1]
			input = input[len(fullMatch)-1:]

			strings := strings.Split(valueString, ",")

			for i, str := range strings {
				if len(str) < 2 || str[0] != '\'' || str[len(str)-1] != '\'' {
					return false
				}
				strings[i] = str[1 : len(str)-1]
			}
			w.stringArray[uint32(variable)] = strings
		case 'M':
			captureMessage := regexp.MustCompile(`^\[(.+?)\](?:,|})`)
			match := captureMessage.FindStringSubmatch(input)
			if match == nil {
				return false
			}

			fullMatch := match[0]
			valueString := match[1]
			input = input[len(fullMatch)-1:]

			msgStrings := strings.Split(valueString, ",")

			var msgs []WinboxMessage
			for _, msgString := range msgStrings {
				tempMsg := WinboxMessage{}
				if !tempMsg.parseJSON(msgString) {
					return false
				}
				msgs = append(msgs, tempMsg)
			}
			w.msgArray[uint32(variable)] = msgs
		default:
			return false
		}

		if len(input) == 0 || (input[0] != ',' && input[0] != '}') {
			return false
		}
		input = input[1:]
	}
	return true
}

func (w *WinboxMessage) hasError() bool {
	_, strExists := w.strings[kErrorString]
	_, u32Exists := w.u32s[kErrorCode]
	return strExists || u32Exists
}

func (w *WinboxMessage) getErrorString() string {
	if w.hasError() {
		if str, exists := w.strings[kErrorString]; exists {
			return str
		} else if code, exists := w.u32s[kErrorCode]; exists {
			switch code {
			case kNotImplemented, kNotImplementedv2:
				return "Feature not implemented"
			case kObjNonexistant, kObjNonexistant2:
				return "Object doesn't exist"
			case kNotPermitted:
				return "Not permitted"
			case kTimeout:
				return "Timeout"
			case kBusy:
				return "Busy"
			default:
				return "Unknown error code"
			}
		}
	}
	return ""
}

func (w *WinboxMessage) getSessionID() uint32 {
	return w.getU32(kSessionId)
}

func (w *WinboxMessage) getBoolean(pName uint32) bool {
	if val, exists := w.bools[pName]; exists {
		return val
	}
	return false
}

func (w *WinboxMessage) getU32(pName uint32) uint32 {
	if val, exists := w.u32s[pName]; exists {
		return val
	}
	return 0
}

func (w *WinboxMessage) getU64(pName uint32) uint64 {
	if val, exists := w.u64s[pName]; exists {
		return val
	}
	return 0
}

func (w *WinboxMessage) getIP6(pName uint32) [16]byte {
	if val, exists := w.ip6s[pName]; exists {
		return val
	}
	return [16]byte{}
}

func (w *WinboxMessage) getRaw(pName uint32) string {
	if val, exists := w.raw[pName]; exists {
		return val
	}
	return ""
}

func (w *WinboxMessage) getString(pName uint32) string {
	if val, exists := w.strings[pName]; exists {
		return val
	}
	return ""
}

func (w *WinboxMessage) getMsg(pName uint32) WinboxMessage {
	if val, exists := w.msgs[pName]; exists {
		return val
	}
	return WinboxMessage{}
}

func (w *WinboxMessage) getBooleanArray(pName uint32) []bool {
	if val, exists := w.boolArray[pName]; exists {
		return val
	}
	return []bool{}
}

func (w *WinboxMessage) getU32Array(pName uint32) []uint32 {
	if val, exists := w.u32Array[pName]; exists {
		return val
	}
	return []uint32{}
}

func (w *WinboxMessage) getU64Array(pName uint32) []uint64 {
	if val, exists := w.u64Array[pName]; exists {
		return val
	}
	return []uint64{}
}

func (w *WinboxMessage) getIP6Array(pName uint32) [][16]byte {
	if val, exists := w.ip6Array[pName]; exists {
		return val
	}
	return [][16]byte{}
}

func (w *WinboxMessage) getStringArray(pName uint32) []string {
	if val, exists := w.stringArray[pName]; exists {
		return val
	}
	return []string{}
}

func (w *WinboxMessage) getMsgArray(pName uint32) []WinboxMessage {
	if val, exists := w.msgArray[pName]; exists {
		return val
	}
	return []WinboxMessage{}
}

func (w *WinboxMessage) getRawArray(pName uint32) []string {
	if val, exists := w.rawArray[pName]; exists {
		return val
	}
	return []string{}
}

func (w *WinboxMessage) setTo(pTo uint32) {
	delete(w.u32Array, kSysTo)

	to := []uint32{pTo}
	w.addU32Array(kSysTo, to)
}

func (w *WinboxMessage) setToWithHandler(pTo, pHandler uint32) {
	delete(w.u32Array, kSysTo)

	to := []uint32{pTo, pHandler}
	w.addU32Array(kSysTo, to)
}

func (w *WinboxMessage) setCommand(pCommand uint32) {
	w.addU32(kCommand, pCommand)
}

func (w *WinboxMessage) setReplyExpected(pReplyExpected bool) {
	w.addBoolean(kReplyExpected, pReplyExpected)
}

func (w *WinboxMessage) setRequestID(pID uint32) {
	w.addU32(kRequestId, pID)
}

func (w *WinboxMessage) setSessionID(pSessionID uint32) {
	w.addU32(kSessionId, pSessionID)
}

func (w *WinboxMessage) addBoolean(pName uint32, pValue bool) {
	w.bools[pName] = pValue
}

func (w *WinboxMessage) addU32(pName, pValue uint32) {
	w.u32s[pName] = pValue
}

func (w *WinboxMessage) addU64(pName uint32, pValue uint64) {
	w.u64s[pName] = pValue
}

func (w *WinboxMessage) addIP6(pName uint32, pValue [16]byte) {
	w.ip6s[pName] = pValue
}

func (w *WinboxMessage) addString(pName uint32, pString string) {
	w.strings[pName] = pString
}

func (w *WinboxMessage) addMsg(pName uint32, pMsg WinboxMessage) {
	w.msgs[pName] = pMsg
}

func (w *WinboxMessage) addRaw(pName uint32, pRaw string) {
	w.raw[pName] = pRaw
}

func (w *WinboxMessage) addBooleanArray(pName uint32, pValue []bool) {
	w.boolArray[pName] = pValue
}

func (w *WinboxMessage) addU32Array(pName uint32, pValue []uint32) {
	w.u32Array[pName] = pValue
}

func (w *WinboxMessage) addU64Array(pName uint32, pValue []uint64) {
	w.u64Array[pName] = pValue
}

func (w *WinboxMessage) addIP6Array(pName uint32, pValue [][16]byte) {
	w.ip6Array[pName] = pValue
}

func (w *WinboxMessage) addStringArray(pName uint32, pValue []string) {
	w.stringArray[pName] = pValue
}

func (w *WinboxMessage) addMsgArray(pName uint32, pValue []WinboxMessage) {
	w.msgArray[pName] = pValue
}

func (w *WinboxMessage) addRawArray(pName uint32, pValue []string) {
	w.rawArray[pName] = pValue
}

func (w *WinboxMessage) eraseU32(pName uint32) {
	delete(w.u32s, pName)
}
