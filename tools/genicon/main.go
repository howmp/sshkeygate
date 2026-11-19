//go:build ignore

// Command genicon turns the original artwork into the icon files the app
// embeds and the .ico the Windows executable carries.
//
// Run it from the repository root:
//
//	go run tools/genicon/main.go
//	go run github.com/akavel/rsrc@latest -ico app/assets/icon.ico -o rsrc_windows_amd64.syso
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
)

const (
	sourcePath = "tools/genicon/source.png"
	pngOutput  = "app/assets/icon.png"
	icoOutput  = "app/assets/icon.ico"
	// trayOutput is the macOS menu bar icon: the same artwork as one colour,
	// which the system tints for the light or dark menu bar.
	trayOutput = "app/assets/tray.png"
	// pngSize is the size embedded for the window and tray.
	pngSize = 256
	// traySize is the size the menu bar asks for, at 2x for Retina.
	traySize = 44
)

// icoSizes are written into the .ico, smallest first.
var icoSizes = []int{16, 20, 24, 32, 40, 48, 64, 128, 256}

func main() {
	src, err := loadPNG(sourcePath)
	if err != nil {
		fail(err)
	}
	if err := os.MkdirAll(filepath.Dir(pngOutput), 0o755); err != nil {
		fail(err)
	}

	if err := writePNG(pngOutput, scale(src, pngSize)); err != nil {
		fail(err)
	}

	// The menu bar icon is the key alone in one colour, its background
	// dropped: macOS tints a template image to match the menu bar, so a
	// drawn background would come out as a filled square.
	if err := writePNG(trayOutput, trayTemplate(scale(src, traySize))); err != nil {
		fail(err)
	}

	var images [][]byte
	for _, size := range icoSizes {
		var buf bytes.Buffer
		if err := png.Encode(&buf, scale(src, size)); err != nil {
			fail(err)
		}
		images = append(images, buf.Bytes())
	}
	if err := os.WriteFile(icoOutput, buildICO(icoSizes, images), 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("wrote %s (%dpx), %s (%dpx) and %s (%d sizes)\n",
		pngOutput, pngSize, trayOutput, traySize, icoOutput, len(icoSizes))
}

// trayTemplate turns the app icon into a template image for the macOS menu
// bar: the key alone, in one colour, with transparency elsewhere.
//
// A template image is masked by its alpha channel and tinted by the system.
// The mark is found by its colour - the ring is green and the prompt navy,
// the background and the space inside the ring near-white - and the holes the
// outline encloses stay transparent, so the icon reads at menu bar size.
func trayTemplate(src image.Image) image.Image {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()

	// The artwork is drawn on a pale rounded square, about #F4FAFB, opaque
	// rather than transparent, so the mark is separated by its colour: the
	// green ring and the navy prompt are far from it in the RGB cube, and
	// the pale space inside the ring is the same colour as the background.
	mark := func(x, y int) bool {
		c := color.NRGBAModel.Convert(src.At(b.Min.X+x, b.Min.Y+y)).(color.NRGBA)
		if c.A == 0 {
			return false
		}
		// How far the pixel is from the background, as a fraction of the
		// largest distance the cube allows. Antialiasing blends towards it,
		// so the threshold sits above the fringe.
		dr := float64(c.R) - 0xF4
		dg := float64(c.G) - 0xFA
		db := float64(c.B) - 0xFB
		dist := math.Sqrt(dr*dr+dg*dg+db*db) / (255 * math.Sqrt(3))
		return dist > 0.22
	}

	// Solid black with the mark's alpha: the system replaces the colour, so
	// only the shape matters.
	out := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if mark(x, y) {
				out.SetNRGBA(x, y, color.NRGBA{R: 0, G: 0, B: 0, A: 255})
			}
		}
	}
	return out
}

func loadPNG(path string) (image.Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return img, nil
}

func writePNG(path string, img image.Image) error {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// scale resizes src to size×size with a box filter.
//
// Averaging happens in premultiplied alpha, so transparent pixels do not
// bleed their colour into the edges of the artwork.
func scale(src image.Image, size int) *image.NRGBA {
	sb := src.Bounds()
	sw, sh := sb.Dx(), sb.Dy()
	dst := image.NewNRGBA(image.Rect(0, 0, size, size))

	for y := 0; y < size; y++ {
		y0 := sb.Min.Y + y*sh/size
		y1 := sb.Min.Y + (y+1)*sh/size
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < size; x++ {
			x0 := sb.Min.X + x*sw/size
			x1 := sb.Min.X + (x+1)*sw/size
			if x1 <= x0 {
				x1 = x0 + 1
			}

			var sumA, sumR, sumG, sumB, count float64
			for sy := y0; sy < y1 && sy < sb.Max.Y; sy++ {
				for sx := x0; sx < x1 && sx < sb.Max.X; sx++ {
					r, g, b, a := src.At(sx, sy).RGBA() // premultiplied, 16-bit
					sumA += float64(a) / 65535
					sumR += float64(r) / 65535
					sumG += float64(g) / 65535
					sumB += float64(b) / 65535
					count++
				}
			}
			if count == 0 || sumA == 0 {
				continue
			}
			dst.SetNRGBA(x, y, color.NRGBA{
				R: clamp(sumR / sumA * 255),
				G: clamp(sumG / sumA * 255),
				B: clamp(sumB / sumA * 255),
				A: clamp(sumA / count * 255),
			})
		}
	}
	return dst
}

// buildICO assembles an icon file whose images are PNG-compressed.
func buildICO(sizes []int, images [][]byte) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint16(0))          // reserved
	binary.Write(&buf, binary.LittleEndian, uint16(1))          // type: icon
	binary.Write(&buf, binary.LittleEndian, uint16(len(sizes))) // count

	offset := 6 + 16*len(sizes)
	for i, size := range sizes {
		dim := byte(size)
		if size >= 256 {
			dim = 0 // 0 means 256 in a directory entry
		}
		buf.WriteByte(dim)                                  // width
		buf.WriteByte(dim)                                  // height
		buf.WriteByte(0)                                    // palette size
		buf.WriteByte(0)                                    // reserved
		binary.Write(&buf, binary.LittleEndian, uint16(1))  // colour planes
		binary.Write(&buf, binary.LittleEndian, uint16(32)) // bits per pixel
		binary.Write(&buf, binary.LittleEndian, uint32(len(images[i])))
		binary.Write(&buf, binary.LittleEndian, uint32(offset))
		offset += len(images[i])
	}
	for _, data := range images {
		buf.Write(data)
	}
	return buf.Bytes()
}

func clamp(v float64) uint8 {
	if v <= 0 {
		return 0
	}
	if v >= 255 {
		return 255
	}
	return uint8(v + 0.5)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "genicon:", err)
	os.Exit(1)
}
