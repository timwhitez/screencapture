package main

import (
	"bytes"
	"context"
	randd "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/jpeg"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"os/signal"
	"runtime"
	"syscall"

	// _ "net/http/pprof"
	"os"
	"strconv"
	"time"

	"github.com/kbinani/screenshot"
	"github.com/mattn/go-mjpeg"
	"github.com/nfnt/resize"
	"github.com/timwhitez/screencapture/d3d"
	forkscreenshot "github.com/timwhitez/screencapture/screenshot"
)

type application struct {
	auth struct {
		username string
		password string
	}
}

var (
	quality int
	passwd  string
	port    string
)

func init() {
	flag.IntVar(&quality, "q", 1, "[optional]screen quality 0:1080p | 1:720p(default) | 2:480p")
	flag.StringVar(&passwd, "s", "", "[optional]secret password (default for random)")
	flag.StringVar(&port, "p", "", "[optional]port (default for random)")
}

func main() {
	flag.Parse()

	app := new(application)
	app.auth.username = "admin"
	pass := RandomString(16)
	if passwd != "" {
		pass = passwd
	}

	app.auth.password = pass
	fmt.Println("Password: " + pass + "\n")

	if app.auth.username == "" {
		log.Fatal("basic auth username must be provided")
	}

	if app.auth.password == "" {
		log.Fatal("basic auth password must be provided")
	}

	n := screenshot.NumActiveDisplays()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	http.HandleFunc("/watch", app.basicAuth(func(w http.ResponseWriter, r *http.Request) {
		screen := r.URL.Query().Get("screen")
		if screen == "" {
			screen = "0"
		}
		screenNo, err := strconv.Atoi(screen)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		if screenNo >= n || screenNo < 0 {
			screenNo = 0
		}

		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title> Screen ` + strconv.Itoa(screenNo) + `</title>
	</head>
		<body style="margin:0">
	<img src="/mjpeg` + strconv.Itoa(screenNo) + `" style="max-width: 100vw; max-height: 100vh;object-fit: contain;display: block;margin: 0 auto;" />
</body>`))
	}))

	framerate := 15
	for i := 0; i < n; i++ {
		fmt.Fprintf(os.Stderr, "Registering stream %d\n", i)
		stream := mjpeg.NewStream()
		defer stream.Close()
		// go streamDisplay(ctx, i, framerate, stream)
		go streamDisplayDXGI(ctx, i, framerate, stream)
		// go captureScreenTranscode(ctx, i, framerate)
		http.HandleFunc(fmt.Sprintf("/mjpeg%d", i), app.basicAuth(stream.ServeHTTP))
	}
	go func() {
		port0 := 10000
		var err error
		if port != "" {
			port0, err = strconv.Atoi(port)
			if err == nil {
				fmt.Println("Listening 127.0.0.1:" + strconv.Itoa(port0))
				err = http.ListenAndServe("127.0.0.1:"+strconv.Itoa(port0), nil)
			}
			if err != nil {
				fmt.Printf(" -> %s\n", "fail")
				port0 = 10000
				for {
					seed := rand.New(rand.NewSource(time.Now().UnixNano()))
					randNum := seed.Intn(40000)
					port0 += randNum
					fmt.Println("Listening 127.0.0.1:" + strconv.Itoa(port0))
					func() {
						defer func() {
							if ok := recover(); ok != nil {
								fmt.Printf(" -> %s\n", "fail")
								port0 = 10000
							}
						}()
						err = http.ListenAndServe("127.0.0.1:"+strconv.Itoa(port0), nil)
						if err != nil {
							panic("unavailable")
						}
					}()
				}
			} else {

			}
		} else {
			port0 = 10000
			for {
				seed := rand.New(rand.NewSource(time.Now().UnixNano()))
				randNum := seed.Intn(40000)
				port0 += randNum
				fmt.Println("Listening 127.0.0.1:" + strconv.Itoa(port0))
				func() {
					defer func() {
						if ok := recover(); ok != nil {
							fmt.Printf(" -> %s\n", "fail")
							port0 = 10000
						}
					}()
					err = http.ListenAndServe("127.0.0.1:"+strconv.Itoa(port0), nil)
					if err != nil {
						panic("unavailable")
					}
				}()
			}
		}

	}()
	<-ctx.Done()
	<-time.After(time.Second)
}

// RandomString - generates random string of given length
func RandomString(len int) string {
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		b := []byte{0x00, 0x00}
		r, _ := randd.Int(randd.Reader, big.NewInt(26))
		b[0] = 65 + byte(r.Int64()) //A = 65
		r, _ = randd.Int(randd.Reader, big.NewInt(26))
		b[1] = 97 + byte(r.Int64()) //a=97
		r, _ = randd.Int(randd.Reader, big.NewInt(2))
		bytes[i] = b[r.Int64()]
	}
	return string(bytes)
}

func (app *application) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte(app.auth.username))
			expectedPasswordHash := sha256.Sum256([]byte(app.auth.password))

			usernameMatch := subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1
			passwordMatch := subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1

			if usernameMatch && passwordMatch {
				next.ServeHTTP(w, r)
				return
			}
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

// Capture using "github.com/kbinani/screenshot" (modified to reuse image.RGBA)
func streamDisplay(ctx context.Context, n int, framerate int, out *mjpeg.Stream) {
	max := screenshot.NumActiveDisplays()
	if n >= max {
		fmt.Printf("Not enough displays\n")
		return
	}
	buf := &bufferFlusher{}
	opts := jpegQuality(75)
	limiter := NewFrameLimiter(framerate)

	var err error
	finalBounds := screenshot.GetDisplayBounds(n)
	imgBuf := image.NewRGBA(finalBounds)

	lastBounds := finalBounds
	for {
		select {
		case <-ctx.Done():
			return
		default:
			limiter.Wait()
		}
		bounds := screenshot.GetDisplayBounds(n)

		x, y, hw, hh := bounds.Min.X, 0, bounds.Dx(), bounds.Dy()
		newBounds := image.Rect(0, 0, int(hw), int(hh))
		if newBounds != lastBounds {
			lastBounds = newBounds
			imgBuf = image.NewRGBA(lastBounds)
		}
		err = forkscreenshot.CaptureImg(imgBuf, int(x), int(y), int(hw), int(hh))
		if err != nil {
			fmt.Printf("Err CaptureImg: %v\n", err)
			continue
		}
		buf.Reset()

		encodeJpeg(buf, imgBuf, opts)
		out.Update(buf.Bytes())
	}
}

// Capture using IDXGIOutputDuplication
//     https://docs.microsoft.com/en-us/windows/win32/api/dxgi1_2/nn-dxgi1_2-idxgioutputduplication
func streamDisplayDXGI(ctx context.Context, n int, framerate int, out *mjpeg.Stream) {
	max := screenshot.NumActiveDisplays()
	if n >= max {
		fmt.Printf("Not enough displays\n")
		return
	}

	// Keep this thread, so windows/d3d11/dxgi can use their threadlocal caches, if any
	runtime.LockOSThread()

	/*
		// Make thread PerMonitorV2 Dpi aware if supported on OS
		// allows to let windows handle BGRA -> RGBA conversion and possibly more things
		if win.IsValidDpiAwarenessContext(win.DpiAwarenessContextPerMonitorAwareV2) {
			_, err := win.SetThreadDpiAwarenessContext(win.DpiAwarenessContextPerMonitorAwareV2)
			if err != nil {
				fmt.Printf("Could not set thread DPI awareness to PerMonitorAwareV2. %v\n", err)
			} else {
				fmt.Printf("Enabled PerMonitorAwareV2 DPI awareness.\n")
			}
		}
	*/

	// Setup D3D11 stuff
	device, deviceCtx, err := d3d.NewD3D11Device()
	if err != nil {
		fmt.Printf("Could not create D3D11 Device. %v\n", err)
		return
	}
	defer device.Release()
	defer deviceCtx.Release()

	var ddup *d3d.OutputDuplicator
	defer func() {
		if ddup != nil {
			ddup.Release()
			ddup = nil
		}
	}()

	buf := &bufferFlusher{Buffer: bytes.Buffer{}}
	var opts *jpeg.Options
	//opts := jpegQuality(50)

	switch quality {
	case 0:
		opts = jpegQuality(50)
	case 1:
		opts = jpegQuality(30)
	case 2:
		opts = jpegQuality(20)
	default:
		opts = jpegQuality(30)
	}

	limiter := NewFrameLimiter(framerate)
	// Create image that can contain the wanted output (desktop)
	finalBounds := screenshot.GetDisplayBounds(n)
	imgBuf := image.NewRGBA(finalBounds)
	lastBounds := finalBounds

	// TODO: This is just there, so that people can see how resizing might look
	switch quality {
	case 0:
		_ = resize.Resize(1920, 1080, imgBuf, resize.Bicubic)
	case 1:
		_ = resize.Resize(1280, 720, imgBuf, resize.Bicubic)
	case 2:
		_ = resize.Resize(720, 480, imgBuf, resize.Bicubic)
	default:
		_ = resize.Resize(1280, 720, imgBuf, resize.Bicubic)
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
			limiter.Wait()
		}
		bounds := screenshot.GetDisplayBounds(n)
		newBounds := image.Rect(0, 0, int(bounds.Dx()), int(bounds.Dy()))
		if newBounds != lastBounds {
			lastBounds = newBounds
			imgBuf = image.NewRGBA(lastBounds)

			// Throw away old ddup
			if ddup != nil {
				ddup.Release()
				ddup = nil
			}
		}
		// create output duplication if doesn't exist yet (maybe due to resolution change)
		if ddup == nil {
			ddup, err = d3d.NewIDXGIOutputDuplication(device, deviceCtx, uint(n))
			if err != nil {
				fmt.Printf("err: %v\n", err)
				continue
			}
		}

		// Grab an image.RGBA from the current output presenter
		err = ddup.GetImage(imgBuf, 0)
		if err != nil {
			if errors.Is(err, d3d.ErrNoImageYet) {
				// don't update
				continue
			}
			fmt.Printf("Err ddup.GetImage: %v\n", err)
			// Retry with new ddup, can occur when changing resolution
			ddup.Release()
			ddup = nil
			continue
		}
		buf.Reset()
		encodeJpeg(buf, imgBuf, opts)
		out.Update(buf.Bytes())
	}
}

// Workaround for jpeg.Encode(), which requires a Flush()
// method to not call `bufio.NewWriter`
type bufferFlusher struct {
	bytes.Buffer
}

func (*bufferFlusher) Flush() error { return nil }
