package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
)

const supersample = 4

func main() {
	output := flag.String("output", filepath.FromSlash("assets/wintracelens.ico"), "ICO output path")
	flag.Parse()

	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		panic(err)
	}
	if err := writeICO(*output, []int{16, 24, 32, 48, 64, 128, 256}); err != nil {
		panic(err)
	}
}

func writeICO(path string, sizes []int) error {
	images := make([][]byte, 0, len(sizes))
	for _, size := range sizes {
		var encoded bytes.Buffer
		if err := png.Encode(&encoded, drawIcon(size)); err != nil {
			return err
		}
		images = append(images, encoded.Bytes())
	}

	var output bytes.Buffer
	_ = binary.Write(&output, binary.LittleEndian, uint16(0))
	_ = binary.Write(&output, binary.LittleEndian, uint16(1))
	_ = binary.Write(&output, binary.LittleEndian, uint16(len(images)))
	offset := 6 + len(images)*16
	for index, data := range images {
		size := sizes[index]
		width := byte(size)
		height := byte(size)
		if size >= 256 {
			width = 0
			height = 0
		}
		output.WriteByte(width)
		output.WriteByte(height)
		output.WriteByte(0)
		output.WriteByte(0)
		_ = binary.Write(&output, binary.LittleEndian, uint16(1))
		_ = binary.Write(&output, binary.LittleEndian, uint16(32))
		_ = binary.Write(&output, binary.LittleEndian, uint32(len(data)))
		_ = binary.Write(&output, binary.LittleEndian, uint32(offset))
		offset += len(data)
	}
	for _, data := range images {
		output.Write(data)
	}
	return os.WriteFile(path, output.Bytes(), 0o644)
}

func drawIcon(size int) *image.NRGBA {
	largeSize := size * supersample
	large := image.NewNRGBA(image.Rect(0, 0, largeSize, largeSize))
	background := color.NRGBA{R: 35, G: 93, B: 177, A: 255}
	accent := color.NRGBA{R: 75, G: 181, B: 214, A: 255}
	white := color.NRGBA{R: 255, G: 255, B: 255, A: 255}

	for y := 0; y < largeSize; y++ {
		for x := 0; x < largeSize; x++ {
			if insideRoundedSquare(float64(x)+0.5, float64(y)+0.5, float64(largeSize), float64(largeSize)*0.20) {
				large.SetNRGBA(x, y, background)
			}
		}
	}

	cx := float64(largeSize) * 0.43
	cy := float64(largeSize) * 0.43
	radius := float64(largeSize) * 0.235
	thickness := float64(largeSize) * 0.065
	for y := 0; y < largeSize; y++ {
		for x := 0; x < largeSize; x++ {
			px := float64(x) + 0.5
			py := float64(y) + 0.5
			distance := math.Hypot(px-cx, py-cy)
			if math.Abs(distance-radius) <= thickness/2 {
				large.SetNRGBA(x, y, white)
				continue
			}
			if distanceToSegment(px, py, float64(largeSize)*0.58, float64(largeSize)*0.58, float64(largeSize)*0.80, float64(largeSize)*0.80) <= thickness/2 {
				large.SetNRGBA(x, y, white)
				continue
			}
			if distance <= radius-thickness && px < cx && py > cy-float64(largeSize)*0.04 && py < cy+float64(largeSize)*0.04 {
				large.SetNRGBA(x, y, accent)
			}
		}
	}

	return downsample(large, size)
}

func insideRoundedSquare(x, y, size, radius float64) bool {
	nearestX := math.Max(radius, math.Min(size-radius, x))
	nearestY := math.Max(radius, math.Min(size-radius, y))
	return math.Hypot(x-nearestX, y-nearestY) <= radius
}

func distanceToSegment(px, py, x1, y1, x2, y2 float64) float64 {
	dx := x2 - x1
	dy := y2 - y1
	lengthSquared := dx*dx + dy*dy
	if lengthSquared == 0 {
		return math.Hypot(px-x1, py-y1)
	}
	t := ((px-x1)*dx + (py-y1)*dy) / lengthSquared
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(x1+t*dx), py-(y1+t*dy))
}

func downsample(source *image.NRGBA, size int) *image.NRGBA {
	target := image.NewNRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a uint32
			for sy := 0; sy < supersample; sy++ {
				for sx := 0; sx < supersample; sx++ {
					pixel := source.NRGBAAt(x*supersample+sx, y*supersample+sy)
					r += uint32(pixel.R)
					g += uint32(pixel.G)
					b += uint32(pixel.B)
					a += uint32(pixel.A)
				}
			}
			count := uint32(supersample * supersample)
			target.SetNRGBA(x, y, color.NRGBA{R: byte(r / count), G: byte(g / count), B: byte(b / count), A: byte(a / count)})
		}
	}
	return target
}
