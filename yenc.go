// Package yenc
// decoder for yenc encoded binaries (yenc.org)
// modded from github.com/chrisfarms/yenc
package yenc

import (
	"bufio"
	"bytes"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"strconv"
	"strings"
	"log"
)

var (
	Debug1 = false
	Debug2 = false
)

func ParseHeaders(inputBytes []byte) map[string]string {
	values := make(map[string]string)
	input := string(inputBytes)
	// get the filename name off the end
	ni := strings.Index(input, "name=")
	if ni > -1 {
		values["name"] = input[ni:]
	} else {
		ni = len(input)
	}
	// get other header values
	for _, header := range strings.Split(input[:ni], " ") {
		kv := strings.SplitN(strings.TrimSpace(header), "=", 2)
		if len(kv) < 2 {
			continue
		}
		values[kv[0]] = kv[1]
	}
	// done
	return values
}

type Part struct {
	// part num
	Number int
	// size from header
	HeaderSize int64
	// size from part trailer
	Size int64
	// file boundarys
	Begin, End int64
	// filename from yenc header
	Name string
	// line length of part
	cols int
	// numer of parts if given
	Total int
	// crc check for this part
	Crc32   uint32
	crcHash hash.Hash32
	// the decoded data
	Body []byte
}

func (p *Part) validate() error {
	// length checks
	if Debug1 {
		log.Printf("yenc.Part.validate() p.Number=%d c.Crc32=%x", p.Number, p.Crc32)
	}
	if int64(len(p.Body)) != p.Size {
		return fmt.Errorf("Error in yenc.Part.validate: Body size %d did not match expected size %d", len(p.Body), p.Size)
	}
	// crc check
	if p.Crc32 > 0 {
		if sum := p.crcHash.Sum32(); sum != p.Crc32 {
			return fmt.Errorf("Error in yenc.Part.validate: crc check failed for part %d expected %x got %x", p.Number, p.Crc32, sum)
		}
		if Debug1 {
			log.Printf("OK yenc.part.validate() p.Number=%d", p.Number)
		}
		return nil
	}
	return fmt.Errorf("Error in yenc.Part.validate: p.Crc32 not set")
}

type decoder struct {
	// the buffered input
	buf *bufio.Reader
	// alternative input as []string
	dat []string
	// whether we are decoding multipart
	multipart bool
	// numer of parts if given
	total int
	// list of parts
	parts []*Part
	// active part
	part *Part
	// overall crc check
	crc32   uint32
	crcHash hash.Hash32
	// are we waiting for an escaped char
	awaitingSpecial bool
}

func (d *decoder) validate() error {
	if Debug1 {
		log.Printf("yenc.decoder.validate() d.part.Number=%d", d.part.Number)
	}
	if d.crc32 > 0 {
		if sum := d.crcHash.Sum32(); sum != d.crc32 {
			return fmt.Errorf("crc check failed expected %x got %x", d.crc32, sum)
		}
		if Debug1 {
			log.Printf("yenc.decoder validated d.part.Number=%d", d.part.Number)
		}
		return nil
	}
	return fmt.Errorf("Error in yenc.decoder.validate d.crc32 not set")
}

func (d *decoder) readHeader() (err error) {
	var s string
	// find the start of the header
	if d.buf != nil {
		for {
			s, err = d.buf.ReadString('\n')
			if err != nil {
				return err
			}
			if len(s) >= 7 && s[:7] == "=ybegin" {
				break
			}
		}
	} else
	if d.dat != nil {
		for _, s = range d.dat { // s is a line
			if len(s) >= 7 && s[:7] == "=ybegin" {
				break
			}
		}
	}
	// split on name= to get name first
	parts := strings.SplitN(s[7:], "name=", 2)
	if len(parts) > 1 {
		d.part.Name = strings.TrimSpace(parts[1])
	}
	// split on sapce for other headers
	parts = strings.Split(parts[0], " ")
	for i, _ := range parts {
		kv := strings.Split(strings.TrimSpace(parts[i]), "=")
		if len(kv) < 2 {
			continue
		}
		switch kv[0] {
		case "size":
			d.part.HeaderSize, _ = strconv.ParseInt(kv[1], 10, 64)
		case "line":
			d.part.cols, _ = strconv.Atoi(kv[1])
		case "part":
			d.part.Number, _ = strconv.Atoi(kv[1])
			d.multipart = true
		case "total":
			d.total, _ = strconv.Atoi(kv[1])
		}
	}
	return nil
}

func (d *decoder) readPartHeader() (err error) {
	var s string
	// find the start of the header
	if d.buf != nil {
		for {
			s, err = d.buf.ReadString('\n')
			if err != nil {
				return err
			}
			if len(s) >= 6 && s[:6] == "=ypart" {
				break
			}
		}
	} else
	if d.dat != nil {
		for _, s = range d.dat { // s is a line
			if len(s) >= 6 && s[:6] == "=ypart" {
				break
			}
		}
	}
	// split on space for headers
	parts := strings.Split(s[6:], " ")
	for i, _ := range parts {
		kv := strings.Split(strings.TrimSpace(parts[i]), "=")
		if len(kv) < 2 {
			continue
		}
		switch kv[0] {
		case "begin":
			d.part.Begin, _ = strconv.ParseInt(kv[1], 10, 64)
		case "end":
			d.part.End, _ = strconv.ParseInt(kv[1], 10, 64)
		}
	}
	return nil
}

func (d *decoder) parseTrailer(line string) error {
	// split on space for headers
	parts := strings.Split(line, " ")
	for i, _ := range parts {
		kv := strings.Split(strings.TrimSpace(parts[i]), "=")
		if len(kv) < 2 {
			continue
		}
		switch kv[0] {
		case "size":
			d.part.Size, _ = strconv.ParseInt(kv[1], 10, 64)
		case "pcrc32":
			if crc64, err := strconv.ParseUint(kv[1], 16, 64); err == nil {
				d.part.Crc32 = uint32(crc64)
			}
		case "crc32":
			if crc64, err := strconv.ParseUint(kv[1], 16, 64); err == nil {
				d.crc32 = uint32(crc64)
			}
		case "part":
			partNum, _ := strconv.Atoi(kv[1])
			if partNum != d.part.Number {
				return fmt.Errorf("yenc: =yend header out of order expected part %d got %d", d.part.Number, partNum)
			}
		}
	}
	return nil
}

func (d *decoder) decode(line []byte) []byte {
	i, j := 0, 0
	for ; i < len(line); i, j = i+1, j+1 {
		// escaped chars yenc42+yenc64
		if d.awaitingSpecial {
			line[j] = (((line[i] - 42) & 255) - 64) & 255
			d.awaitingSpecial = false
			// if escape char - then skip and backtrack j
		} else if line[i] == '=' {
			d.awaitingSpecial = true
			j--
			continue
			// normal char, yenc42
		} else {
			line[j] = (line[i] - 42) & 255
		}
	}
	// return the new (possibly shorter) slice
	// shorter because of the escaped chars
	return line[:len(line)-(i-j)]
}

func (d *decoder) readBody() error {
	// ready the part body
	d.part.Body = make([]byte, 0)
	// reset special
	d.awaitingSpecial = false
	// setup crc hash
	d.part.crcHash = crc32.NewIEEE()
	// each line
	if d.buf != nil {
		for {
			line, err := d.buf.ReadBytes('\n')
			if err != nil {
				return err
			}
			// strip linefeeds (some use CRLF some LF)
			line = bytes.TrimRight(line, "\r\n")
			// check for =yend
			if len(line) >= 5 && string(line[:5]) == "=yend" {
				return d.parseTrailer(string(line))
			}
			// decode
			b := d.decode(line)
			// update hashs
			d.part.crcHash.Write(b)
			d.crcHash.Write(b)
			// decode
			d.part.Body = append(d.part.Body, b...)
		}
	} else
	if d.dat != nil {
		if Debug1 {}
		log.Printf("yenc.decoder readBody d.dat=%d", len(d.dat))
		for i, line := range d.dat {
			if len(line) >= 5 && string(line[:5]) == "=yend" {
				return d.parseTrailer(line)
			}
			// decode
			b := d.decode([]byte(line))
			log.Printf("yenc.decoder readBody i=%d d.dat=%d len(b)=%d len(line)=%d", i, len(d.dat), len(b), len(line))
			// update hashs
			d.part.crcHash.Write(b)
			d.crcHash.Write(b)
			// decode
			d.part.Body = append(d.part.Body, b...)
		}
	}
	return fmt.Errorf("Error unexpected EOF in yenc.decoder.readBody")
}

func (d *decoder) run() error {
	// init hash
	d.crcHash = crc32.NewIEEE()
	// for each part
	for {
		// create a part
		d.part = new(Part)
		// read the header
		if err := d.readHeader(); err != nil {
			return err
		}
		if Debug2 {
			log.Printf("yenc.decoder.run: #1 done d.readHeader() @Number=%d", d.part.Number)
		}

		// read part header if available
		if d.multipart {
			if err := d.readPartHeader(); err != nil {
				return err
			}
		}
		if Debug2 {
			log.Printf("yenc.decoder.run: #2 done d.readPartHeader @Number=%d", d.part.Number)
		}
		// decode the part body
		if err := d.readBody(); err != nil {
			return err
		}
		if Debug2 {
			log.Printf("yenc.decoder.run: #3 done d.readBody @Number=%d", d.part.Number)
		}

		// validate part
		if err := d.part.validate(); err != nil {
			log.Printf("Error yenc.decoder.run: validate @Number=%d err='%v'", d.part.Number, err)
			return err
		}
		// add part to list
		d.parts = append(d.parts, d.part)
		if Debug2 {
			log.Printf("yenc.decoder.run: #4 done d.validate @Number=%d parts=%d", d.part.Number, len(d.parts))
		}
	}
	return nil
}

// return a single part from yenc data
func DecodeSlice(input []string) (part *Part, err error) {
	d := &decoder{dat: input}
	if err = d.run(); err != nil && err != io.EOF {
		log.Printf("Error in yenc.Decode #1 err='%v'", err)
		return nil, err
	}
	if len(d.parts) == 0 {
		log.Printf("Error in yenc.Decode #2 'len(d.parts) == 0' err='%v'", err)
		return nil, fmt.Errorf("no yenc parts found")
	}
	// validate multipart only if all parts are present
	//if !d.multipart || len(d.parts) == d.parts[len(d.parts)-1].Number { //  ?????????
	if d.multipart && len(d.parts) > 1 && len(d.parts) == d.parts[len(d.parts)-1].Number {
		if Debug1 {
			log.Printf("yenc.Decode d.validate() d.multipart=%t parts=%d", d.multipart, len(d.parts))
		}
		if err := d.validate(); err != nil {
			log.Printf("Error in yenc.Decode #3 d.validate err='%v'", err)
			return nil, err
		}
	}
	if d.total > 0 {
		d.parts[0].Total = d.total
	}
	if Debug1 {
		log.Printf("OK yenc.Decode return yPart.Number=%d Body=%d parts=%d", d.parts[0].Number, len(d.parts[0].Body), len(d.parts))
	}
	return d.parts[0], nil
} // end func DecodeSlice

func Decode(input io.Reader) (part *Part, err error) {
	d := &decoder{buf: bufio.NewReader(input)}
	if err = d.run(); err != nil && err != io.EOF {
		log.Printf("Error in yenc.Decode #1 err='%v'", err)
		return nil, err
	}
	if len(d.parts) == 0 {
		log.Printf("Error in yenc.Decode #2 'len(d.parts) == 0' err='%v'", err)
		return nil, fmt.Errorf("no yenc parts found")
	}
	// validate multipart only if all parts are present
	//if !d.multipart || len(d.parts) == d.parts[len(d.parts)-1].Number { //  ?????????
	if d.multipart && len(d.parts) > 1 && len(d.parts) == d.parts[len(d.parts)-1].Number {
		if Debug1 {
			log.Printf("yenc.Decode d.validate() d.multipart=%t parts=%d", d.multipart, len(d.parts))
		}
		if err := d.validate(); err != nil {
			log.Printf("Error in yenc.Decode #3 d.validate err='%v'", err)
			return nil, err
		}
	}
	if d.total > 0 {
		d.parts[0].Total = d.total
	}
	if Debug1 {
		log.Printf("OK yenc.Decode return yPart.Number=%d Body=%d parts=%d", d.parts[0].Number, len(d.parts[0].Body), len(d.parts))
	}
	return d.parts[0], nil
} // end func Decode
