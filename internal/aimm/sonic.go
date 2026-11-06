package aimm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	rttypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/google/uuid"
)

// BidiRuntime is the bidirectional-stream call of the Bedrock runtime client.
type BidiRuntime interface {
	InvokeModelWithBidirectionalStream(ctx context.Context, in *bedrockruntime.InvokeModelWithBidirectionalStreamInput, o ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelWithBidirectionalStreamOutput, error)
}

// Audio formats of Nova Sonic: it takes 16 kHz 16-bit mono PCM and answers 24 kHz 16-bit mono PCM.
const (
	SonicInRate  = 16000
	SonicOutRate = 24000
)

// SonicConfig tunes a session.
type SonicConfig struct {
	System      string
	Voice       string // matthew, tiffany, amy and the voices of the model (default tiffany)
	MaxTokens   int
	Temperature float64
}

// SonicEvent is what the model sends back.
type SonicEvent struct {
	Kind  string // text | audio | usage | done | error
	Role  string // USER (what it heard) | ASSISTANT
	Text  string
	Stage string // text: SPECULATIVE (draft, replaced by the FINAL one) | FINAL | empty
	Audio []byte // 24 kHz PCM16 when Kind == audio
	In    int    // usage: input tokens (speech+text)
	Out   int
	Err   error
}

// SonicSession is one live conversation turn stream.
type SonicSession struct {
	stream  *bedrockruntime.InvokeModelWithBidirectionalStreamEventStream
	ctx     context.Context
	cancel  context.CancelFunc
	prompt  string
	audioID string
	mu      sync.Mutex
	ended   bool
	Events  chan SonicEvent
}

func (s *SonicSession) send(ev map[string]any) error {
	b, err := json.Marshal(map[string]any{"event": ev})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stream.Writer.Send(s.ctx, &rttypes.InvokeModelWithBidirectionalStreamInputMemberChunk{Value: rttypes.BidirectionalInputPayloadPart{Bytes: b}})
}

// StartSonic opens the stream, sends the session, prompt and system prompt events, and opens the user audio content.
func StartSonic(ctx context.Context, rt BidiRuntime, m Model, cfg SonicConfig) (*SonicSession, error) {
	if m.Family != FamNovaSonic {
		return nil, fmt.Errorf("%w: %s is not a speech-to-speech model", ErrUnsupported, m.ID)
	}
	if cfg.Voice == "" {
		cfg.Voice = "tiffany"
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 1024
	}
	if cfg.Temperature <= 0 {
		cfg.Temperature = 0.7
	}
	if cfg.System == "" {
		cfg.System = "You are a friendly assistant. Answer in the language the user speaks, in short spoken sentences."
	}
	cctx, cancel := context.WithCancel(ctx)
	out, err := rt.InvokeModelWithBidirectionalStream(cctx, &bedrockruntime.InvokeModelWithBidirectionalStreamInput{ModelId: aws.String(invokeID(m))})
	if err != nil {
		cancel()
		return nil, ClassifyAWS(err)
	}
	s := &SonicSession{stream: out.GetStream(), ctx: cctx, cancel: cancel, prompt: uuid.NewString(), audioID: uuid.NewString(), Events: make(chan SonicEvent, 64)}
	sysID := uuid.NewString()
	steps := []map[string]any{
		{"sessionStart": map[string]any{"inferenceConfiguration": map[string]any{"maxTokens": cfg.MaxTokens, "topP": 0.9, "temperature": cfg.Temperature}}},
		{"promptStart": map[string]any{"promptName": s.prompt,
			"textOutputConfiguration":  map[string]any{"mediaType": "text/plain"},
			"audioOutputConfiguration": map[string]any{"mediaType": "audio/lpcm", "sampleRateHertz": SonicOutRate, "sampleSizeBits": 16, "channelCount": 1, "voiceId": cfg.Voice, "encoding": "base64", "audioType": "SPEECH"}}},
		{"contentStart": map[string]any{"promptName": s.prompt, "contentName": sysID, "type": "TEXT", "interactive": false, "role": "SYSTEM", "textInputConfiguration": map[string]any{"mediaType": "text/plain"}}},
		{"textInput": map[string]any{"promptName": s.prompt, "contentName": sysID, "content": cfg.System}},
		{"contentEnd": map[string]any{"promptName": s.prompt, "contentName": sysID}},
		{"contentStart": map[string]any{"promptName": s.prompt, "contentName": s.audioID, "type": "AUDIO", "interactive": true, "role": "USER",
			"audioInputConfiguration": map[string]any{"mediaType": "audio/lpcm", "sampleRateHertz": SonicInRate, "sampleSizeBits": 16, "channelCount": 1, "audioType": "SPEECH", "encoding": "base64"}}},
	}
	for _, st := range steps {
		if err := s.send(st); err != nil {
			s.Close()
			return nil, ClassifyAWS(err)
		}
	}
	go s.read()
	return s, nil
}

func (s *SonicSession) read() {
	defer close(s.Events)
	stage := ""
	for ev := range s.stream.Reader.Events() {
		chunk, ok := ev.(*rttypes.InvokeModelWithBidirectionalStreamOutputMemberChunk)
		if !ok {
			continue
		}
		var m struct {
			Event map[string]json.RawMessage `json:"event"`
		}
		if json.Unmarshal(chunk.Value.Bytes, &m) != nil {
			continue
		}
		for name, raw := range m.Event {
			switch name {
			case "contentStart":
				var cs struct {
					Fields string `json:"additionalModelFields"`
				}
				_ = json.Unmarshal(raw, &cs)
				stage = ""
				if strings.Contains(cs.Fields, "SPECULATIVE") {
					stage = "SPECULATIVE"
				} else if strings.Contains(cs.Fields, "FINAL") {
					stage = "FINAL"
				}
			case "textOutput":
				var t struct {
					Content string `json:"content"`
					Role    string `json:"role"`
				}
				_ = json.Unmarshal(raw, &t)
				if strings.HasPrefix(t.Content, "{") && strings.Contains(t.Content, "interrupted") {
					continue // barge-in marker, not speech
				}
				s.emit(SonicEvent{Kind: "text", Role: t.Role, Text: t.Content, Stage: stage})
			case "audioOutput":
				var a struct {
					Content string `json:"content"`
				}
				_ = json.Unmarshal(raw, &a)
				if b, err := base64.StdEncoding.DecodeString(a.Content); err == nil && len(b) > 0 {
					s.emit(SonicEvent{Kind: "audio", Role: "ASSISTANT", Audio: b})
				}
			case "usageEvent":
				var u struct {
					Details struct {
						Total struct {
							Input struct {
								Speech int `json:"speechTokens"`
								Text   int `json:"textTokens"`
							} `json:"input"`
							Output struct {
								Speech int `json:"speechTokens"`
								Text   int `json:"textTokens"`
							} `json:"output"`
						} `json:"total"`
					} `json:"details"`
				}
				_ = json.Unmarshal(raw, &u)
				s.emit(SonicEvent{Kind: "usage", In: u.Details.Total.Input.Speech + u.Details.Total.Input.Text, Out: u.Details.Total.Output.Speech + u.Details.Total.Output.Text})
			case "completionEnd":
				s.emit(SonicEvent{Kind: "done"})
			}
		}
	}
	if err := s.stream.Reader.Err(); err != nil && s.ctx.Err() == nil {
		s.emit(SonicEvent{Kind: "error", Err: ClassifyAWS(err)})
	}
}

func (s *SonicSession) emit(e SonicEvent) {
	select {
	case s.Events <- e:
	case <-s.ctx.Done():
	}
}

// Audio sends PCM16 16 kHz mono in chunks of about 32 ms.
func (s *SonicSession) Audio(pcm []byte) error {
	const chunk = 1024
	for len(pcm) > 0 {
		n := chunk
		if n > len(pcm) {
			n = len(pcm)
		}
		if err := s.send(map[string]any{"audioInput": map[string]any{"promptName": s.prompt, "contentName": s.audioID, "content": base64.StdEncoding.EncodeToString(pcm[:n])}}); err != nil {
			return ClassifyAWS(err)
		}
		pcm = pcm[n:]
	}
	return nil
}

// EndInput closes the user audio: the model answers what it has heard. The stream stays open until Finish.
func (s *SonicSession) EndInput() error {
	if s.ended {
		return nil
	}
	s.ended = true
	for _, ev := range []map[string]any{
		{"contentEnd": map[string]any{"promptName": s.prompt, "contentName": s.audioID}},
	} {
		if err := s.send(ev); err != nil {
			return ClassifyAWS(err)
		}
	}
	return nil
}

// Finish ends the prompt and the session once the answer is complete.
func (s *SonicSession) Finish() error {
	for _, ev := range []map[string]any{{"promptEnd": map[string]any{"promptName": s.prompt}}, {"sessionEnd": map[string]any{}}} {
		if err := s.send(ev); err != nil {
			return ClassifyAWS(err)
		}
	}
	return nil
}

// Close ends the stream.
func (s *SonicSession) Close() {
	s.cancel()
	_ = s.stream.Close()
}

// TalkResult is the outcome of a file-mode turn.
type TalkResult struct {
	Heard     string  // what the model understood
	Answer    string  // the text of its spoken answer
	Audio     []byte  // 24 kHz PCM16 mono
	Seconds   float64 // audio sent
	InTokens  int
	OutTokens int
}

// TalkFile sends one recorded utterance (PCM16 16 kHz mono) and collects the spoken answer.
func TalkFile(ctx context.Context, rt BidiRuntime, m Model, cfg SonicConfig, pcm []byte, timeout time.Duration) (*TalkResult, error) {
	if len(pcm) < SonicInRate*2/4 {
		return nil, BadInput("the audio is shorter than a quarter of a second")
	}
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	s, err := StartSonic(ctx, rt, m, cfg)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	// The model detects the end of the turn from silence in a live stream, so after the speech Capsule keeps sending paced
	// silence until the answer is complete (the stream is closed by the audio content ending only after that).
	if err := s.Audio(pcm); err != nil {
		return nil, err
	}
	stop := make(chan struct{})
	fed := make(chan struct{})
	go func() {
		defer close(fed)
		quiet := make([]byte, SonicInRate/10*2) // 100 ms
		tk := time.NewTicker(100 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-tk.C:
				if s.Audio(quiet) != nil {
					return
				}
			}
		}
	}()
	finish := func() { close(stop); <-fed; _ = s.EndInput(); _ = s.Finish() }
	defer func() {
		select {
		case <-stop:
		default:
			close(stop)
			<-fed
		}
	}()
	res := &TalkResult{Seconds: float64(len(pcm)) / (SonicInRate * 2)}
	var heard, answer, draft strings.Builder
	// The answer is complete when the model has sent audio and then nothing for a while (it keeps the stream open waiting for more speech).
	idle := time.NewTimer(time.Hour)
	defer idle.Stop()
	got := false
	for open := true; open; {
		var ev SonicEvent
		select {
		case e, ok := <-s.Events:
			if !ok {
				open = false
				continue
			}
			ev = e
		case <-idle.C:
			finish()
			open = false
			continue
		}
		if ev.Kind == "audio" || ev.Kind == "text" {
			if got {
				idle.Reset(3 * time.Second)
			}
		}
		switch ev.Kind {
		case "text":
			if ev.Role == "USER" {
				heard.WriteString(ev.Text)
			} else if ev.Role == "ASSISTANT" {
				if ev.Stage == "SPECULATIVE" {
					draft.WriteString(ev.Text)
				} else {
					answer.WriteString(ev.Text)
				}
			}
		case "audio":
			res.Audio = append(res.Audio, ev.Audio...)
			if !got {
				got = true
				idle.Reset(3 * time.Second)
			}
		case "usage":
			res.InTokens, res.OutTokens = ev.In, ev.Out
		case "error":
			return nil, ev.Err
		}
		if ev.Kind == "done" {
			finish()
			open = false
		}
	}
	if ctx.Err() != nil && len(res.Audio) == 0 {
		return nil, errors.New("timed out waiting for the model's answer")
	}
	res.Heard, res.Answer = strings.TrimSpace(heard.String()), strings.TrimSpace(answer.String())
	if res.Answer == "" {
		res.Answer = strings.TrimSpace(draft.String()) // some models label only the draft stage
	}
	return res, nil
}

// WAV wraps raw PCM16 mono in a WAV header.
func WAV(pcm []byte, rate int) []byte {
	h := make([]byte, 44)
	le32 := func(o int, v uint32) { h[o], h[o+1], h[o+2], h[o+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24) }
	le16 := func(o int, v uint16) { h[o], h[o+1] = byte(v), byte(v>>8) }
	copy(h[0:], "RIFF")
	le32(4, uint32(36+len(pcm)))
	copy(h[8:], "WAVEfmt ")
	le32(16, 16)
	le16(20, 1)
	le16(22, 1)
	le32(24, uint32(rate))
	le32(28, uint32(rate*2))
	le16(32, 2)
	le16(34, 16)
	copy(h[36:], "data")
	le32(40, uint32(len(pcm)))
	return append(h, pcm...)
}

// PCMFromWAV returns the PCM16 mono payload of a WAV file and its sample rate; it rejects any other layout.
func PCMFromWAV(b []byte) (pcm []byte, rate int, err error) {
	if len(b) < 44 || string(b[0:4]) != "RIFF" || string(b[8:12]) != "WAVE" {
		return nil, 0, BadInput("not a WAV file")
	}
	le16 := func(o int) int { return int(b[o]) | int(b[o+1])<<8 }
	le32 := func(o int) int { return le16(o) | le16(o+2)<<16 }
	pos := 12
	var fmtOK bool
	for pos+8 <= len(b) {
		id, size := string(b[pos:pos+4]), le32(pos+4)
		body := pos + 8
		switch id {
		case "fmt ":
			if size < 16 || body+16 > len(b) {
				return nil, 0, BadInput("broken WAV header")
			}
			if le16(body) != 1 || le16(body+2) != 1 || le16(body+14) != 16 {
				return nil, 0, BadInput("WAV must be PCM 16-bit mono")
			}
			rate, fmtOK = le32(body+4), true
		case "data":
			if !fmtOK {
				return nil, 0, BadInput("WAV data before format")
			}
			end := body + size
			if end > len(b) || size < 0 {
				end = len(b)
			}
			return b[body:end], rate, nil
		}
		pos = body + size + size%2
	}
	return nil, 0, BadInput("WAV has no data")
}

// Resample16 converts PCM16 mono from rate to 16 kHz by linear interpolation (speech quality is enough for recognition).
func Resample16(pcm []byte, rate int) []byte {
	if rate == SonicInRate || rate <= 0 {
		return pcm
	}
	n := len(pcm) / 2
	sample := func(i int) float64 {
		if i < 0 {
			i = 0
		}
		if i >= n {
			i = n - 1
		}
		return float64(int16(uint16(pcm[2*i]) | uint16(pcm[2*i+1])<<8))
	}
	outN := int(float64(n) * SonicInRate / float64(rate))
	out := make([]byte, outN*2)
	for i := 0; i < outN; i++ {
		pos := float64(i) * float64(rate) / SonicInRate
		i0 := int(pos)
		f := pos - float64(i0)
		v := int16(sample(i0)*(1-f) + sample(i0+1)*f)
		out[2*i], out[2*i+1] = byte(uint16(v)), byte(uint16(v)>>8)
	}
	return out
}
