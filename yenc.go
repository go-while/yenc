// another yenc decoder (experimental/testing)
// modded from: github.com/chrisfarms/yenc
// to be used in NZBreX (nzbrefreshX)
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
	Debug3 = false
	DebugThis11 = false
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

type Decoder struct {
	// set <= 0 if unknown or any number but mostly only 1!
	toCheck int64
	// the buffered input
	Buf *bufio.Reader
	// alternative input as []string
	Dat []*string
	// whether we are decoding multipart
	multipart bool
	// numer of parts if given
	total int
	// list of parts
	parts []*Part
	// active part
	part *Part
	// overall crc check
	Fullcrc32   uint32
	crcHash hash.Hash32
	// are we waiting for an escaped char
	awaitingSpecial bool
}

// you should supply only one: ior or in1 or in2!
// toCheck should be <= 0 if unknown or any number but mostly only 1!
// if 'in2 []string' is supplied:
//   you have to set 'toCheck' or it will not get an EOF and will not release!
func NewDecoder(ior io.Reader, in1 []byte, in2 []*string, toCheck int64) *Decoder {
	var decoder Decoder
	if ior != nil {
		decoder.Buf = bufio.NewReader(ior)
	} else
	if in1 != nil {
		decoder.Buf = bufio.NewReader(bytes.NewReader(in1))
	} else
	if in2 != nil {
		decoder.Dat = in2
	}
	decoder.toCheck = toCheck
	return &decoder
} // end func yenc.NewDecoder(in1, in2)

func (d *Decoder) validate() error {
	if Debug1 {
		log.Printf("yenc.Decoder.validate() d.part.Number=%d", d.part.Number)
	}
	if d.Fullcrc32 > 0 {
		if sum := d.crcHash.Sum32(); sum != d.Fullcrc32 {
			return fmt.Errorf("crc check failed expected %x got %x", d.Fullcrc32, sum)
		}
		if Debug1 {
			log.Printf("yenc.Decoder validated d.part.Number=%d", d.part.Number)
		}
		return nil
	}
	return fmt.Errorf("Error in yenc.Decoder.validate d.Fullcrc32 not set")
}

func (d *Decoder) readHeader() (err error) {
	var s string
	// find the start of the header
	if d.Buf != nil {
		for {
			s, err = d.Buf.ReadString('\n')
			if err != nil {
				return err
			}
			if len(s) >= 7 && s[:7] == "=ybegin" {
				break
			}
		}
	} else
	if d.Dat != nil {
		for _, sptr := range d.Dat { // s is a line
			if len(*sptr) >= 7 && string(*sptr)[:7] == "=ybegin" {
				s = *sptr
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

func (d *Decoder) readPartHeader() (err error) {
	var s string
	// find the start of the header
	if d.Buf != nil {
		for {
			s, err = d.Buf.ReadString('\n')
			if err != nil {
				return err
			}
			if len(s) >= 6 && s[:6] == "=ypart" {
				break
			}
		}
	} else
	if d.Dat != nil {
		for _, sptr := range d.Dat { // s is a line
			if len(*sptr) >= 6 && string(*sptr)[:6] == "=ypart" {
				s = *sptr
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

func (d *Decoder) parseTrailer(line string) error {
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
				d.Fullcrc32 = uint32(crc64)
				d.part.Crc32 = uint32(crc64) // why it has not been set by default... i dont know
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

func (d *Decoder) decode(line []byte) []byte {
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

func (d *Decoder) readBody() error {
	// ready the part body
	d.part.Body = make([]byte, 0)
	// reset special
	d.awaitingSpecial = false
	// setup crc hash
	d.part.crcHash = crc32.NewIEEE()
	// each line
	if d.Buf != nil {
		for {
			line, err := d.Buf.ReadBytes('\n')
			if err != nil {
				log.Printf("Error in yenc.Decoder.readBody d.Buf.ReadBytes err='%v'", err)
				return err
			}
			// strip linefeeds (some use CRLF some LF)
			line = bytes.TrimRight(line, "\r\n")
			// check for =yend
			if len(line) >= 5 && string(line[:5]) == "=yend" {
				if Debug1 {
					log.Printf("yenc.Decoder d.Buf =yend d.part.Body=%d", len(d.part.Body))
				}
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
	if d.Dat != nil {
		if Debug1 {
			log.Printf("yenc.Decoder readBody lines d.Dat=%d", len(d.Dat))
		}
		for i, line := range d.Dat {
			if len(*line) == 0 {
				continue
			}
			// Skip yenc headers or metadata lines
			if strings.HasPrefix(*line, "=ybegin") || strings.HasPrefix(*line, "=ypart") {
				continue
			}
			if len(*line) >= 5 && string(*line)[:5] == "=yend" {
				if Debug2 {
					log.Printf("yenc.Decoder d.Dat =yend d.part.Body=%d", len(d.part.Body))
				}
				return d.parseTrailer(*line)
			}
			// decode
			b := d.decode([]byte(*line))
			if Debug2 {
				log.Printf("yenc.Decoder readBody i=%d/d.Dat=%d len(line)=%d got len(b)=%d", i, len(d.Dat), len(*line), len(b))
			}
			// update hashs
			d.part.crcHash.Write(b)
			d.crcHash.Write(b)
			// decode
			d.part.Body = append(d.part.Body, b...)
		}
	}
	return fmt.Errorf("Error unexpected EOF in yenc.Decoder.readBody")
}

func (d *Decoder) run() error {
	// init hash
	d.crcHash = crc32.NewIEEE()
	var checked int64 = 0
	processed := make(map[string]map[int]bool)
	// for each part
	for {
		// create a part
		d.part = new(Part)

		// read the header
		if err := d.readHeader(); err != nil {
			if DebugThis11 {
				// when reading from io.reader or with []bytes
				// ^ we use a buffer which clears out while reading
				// : but with []*string we won't hit an io.EOF while iterating over and over again!
				// ! results in oom quickly as it generates new parts and fills them all with the same!
				log.Printf("Debug readHeader err='%v'", err)
			}
			return err
		}
		if Debug2 {
			log.Printf("yenc.Decoder.run: #1 done d.readHeader() @Number=%d", d.part.Number)
		}
		if d.part.Name == "" {
			return fmt.Errorf("ERROR in yenc.Decoder.run() empty Name field fn='%s' part=%d", d.part.Name, d.part.Number)
		}
		if processed[d.part.Name] == nil {
			processed[d.part.Name] = make(map[int]bool, d.total)
		}
		if processed[d.part.Name][d.part.Number] {
			return fmt.Errorf("ERROR in yenc.Decoder.run() already processed fn='%s' part=%d", d.part.Name, d.part.Number)
		}
		processed[d.part.Name][d.part.Number] = true // set it here or later? should not matter as we return on any err

		//log.Printf("yenc.Decoder.run: process #1 d.part.Number=%d", d.part.Number)

		// read part header if available
		if d.multipart {
			if err := d.readPartHeader(); err != nil {
				log.Printf("Debug readPartHeader err='%v'", err)
				return err
			}
		}
		if Debug2 {
			log.Printf("yenc.Decoder.run: #2 done d.readPartHeader @Number=%d", d.part.Number)
		}
		//log.Printf("yenc.Decoder.run: process #2 d.part.Number=%d", d.part.Number)

		// decode the part body
		if err := d.readBody(); err != nil {
			log.Printf("Debug readBody err='%v'", err)
			return err
		}
		if Debug2 {
			log.Printf("yenc.Decoder.run: #3 done d.readBody @Number=%d", d.part.Number)
		}
		//log.Printf("yenc.Decoder.run: process #3 d.part.Number=%d", d.part.Number)

		// validate part
		if err := d.part.validate(); err != nil {
			log.Printf("Error yenc.Decoder.run: validate @Number=%d err='%v' d.part='%#v'", d.part.Number, err, d.part)
			return err
		}
		//log.Printf("yenc.Decoder.run: process #4 d.part.Number=%d", d.part.Number)

		// add part to list
		d.parts = append(d.parts, d.part)

		if Debug3 {
			log.Printf("yenc.Decoder.run: #4 done d.validate @Number=%d parts=%d", d.part.Number, len(d.parts))
		}

		checked++
		if d.toCheck > 0 && checked == d.toCheck {
			break
		}
		//log.Printf("processed d.part.Number=%d", d.part.Number)
	}
	return nil
} // end func d.run()

// return a single part from yenc data
func (d *Decoder) DecodeSlice() (part *Part, err error) {
	//d := &Decoder{dat: input}
	if err = d.run(); err != nil && err != io.EOF {
		log.Printf("Error in yenc.DecodeSlice #1 err='%v'", err)
		return nil, err
	}
	if len(d.parts) == 0 {
		log.Printf("Error in yenc.DecodeSlice #2 'len(d.parts) == 0' err='%v'", err)
		return nil, fmt.Errorf("no yenc parts found")
	}
	// validate multipart only if all parts are present
	//if !d.multipart || len(d.parts) == d.parts[len(d.parts)-1].Number { //  ?????????
	if d.multipart && len(d.parts) > 1 && len(d.parts) == d.parts[len(d.parts)-1].Number {
		if Debug3 {
			log.Printf("yenc.DecodeSlice d.validate() d.multipart=%t parts=%d", d.multipart, len(d.parts))
		}
		if err := d.validate(); err != nil {
			log.Printf("Error in yenc.DecodeSlice #3 d.validate err='%v'", err)
			return nil, err
		}
	}
	if Debug3 {
		log.Printf("OK yenc.DecodeSlice return yPart.Number=%d Body=%d parts=%d", d.parts[0].Number, len(d.parts[0].Body), len(d.parts))
	}
	return d.parts[0], nil
} // end func DecodeSlice

func (d *Decoder) Decode() (part *Part, err error) {
	//d := &Decoder{buf: bufio.NewReader(input)}
	if err = d.run(); err != nil && err != io.EOF {
		return nil, fmt.Errorf("Error in yenc.Decode #1 err='%v'", err)
	}
	if len(d.parts) == 0 {
		return nil, fmt.Errorf("Error in yenc.Decode #2 'len(d.parts) == 0' err='%#v'", err)
	}
	// validate multipart only if all parts are present
	//if !d.multipart || len(d.parts) == d.parts[len(d.parts)-1].Number { //  ?????????
	if d.multipart && len(d.parts) > 1 && len(d.parts) == d.parts[len(d.parts)-1].Number {
		if Debug3 {
			log.Printf("yenc.Decode d.validate() d.multipart=%t parts=%d", d.multipart, len(d.parts))
		}
		if err := d.validate(); err != nil {
			return nil, fmt.Errorf("Error in yenc.Decode #3 d.validate err='%v'", err)
		}
	}
	if Debug3 {
		log.Printf("OK yenc.Decode return yPart.Number=%d Body=%d parts=%d", d.parts[0].Number, len(d.parts[0].Body), len(d.parts))
	}
	return d.parts[0], nil
} // end func Decode
