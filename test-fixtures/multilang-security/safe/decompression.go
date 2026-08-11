package safe

import (
	"compress/zlib"
	"io"
)

func Expand(destination io.Writer, compressed io.Reader) error {
	reader, err := zlib.NewReader(compressed)
	if err != nil {
		return err
	}
	defer reader.Close()
	_, err = io.Copy(destination, io.LimitReader(reader, 1<<20))
	return err
}
