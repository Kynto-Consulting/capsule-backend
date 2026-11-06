package aimm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/polly"
	pollytypes "github.com/aws/aws-sdk-go-v2/service/polly/types"
	"github.com/aws/aws-sdk-go-v2/service/transcribe"
	trtypes "github.com/aws/aws-sdk-go-v2/service/transcribe/types"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------- Polly (text to speech)

// PollyAPI is the Polly client surface in use.
type PollyAPI interface {
	SynthesizeSpeech(ctx context.Context, in *polly.SynthesizeSpeechInput, o ...func(*polly.Options)) (*polly.SynthesizeSpeechOutput, error)
	DescribeVoices(ctx context.Context, in *polly.DescribeVoicesInput, o ...func(*polly.Options)) (*polly.DescribeVoicesOutput, error)
}

// SpeakRequest asks for speech.
type SpeakRequest struct {
	Text   string
	Voice  string // Polly voice id (Lupe, Joanna, Mia...); empty picks one for Lang
	Lang   string // es-US, en-US...; empty: es-US
	Format string // mp3 (default) | ogg | pcm
	Rate   string // optional prosody rate: x-slow slow medium fast x-fast or a percentage like 90%
}

// Speech is the synthesized audio.
type Speech struct {
	Audio       []byte
	ContentType string
	Format      string
	Voice       string
	Chars       int
}

// MaxSpeechChars is the limit per request (Polly bills characters and rejects > 3000 per call; longer text is split on sentences).
const MaxSpeechChars = 20000

var defaultVoices = map[string]string{"es-US": "Lupe", "es-ES": "Lucia", "es-MX": "Mia", "en-US": "Joanna", "en-GB": "Amy", "pt-BR": "Camila", "fr-FR": "Lea", "de-DE": "Vicki", "it-IT": "Bianca"}

// Speak synthesizes req.Text with the engine of model m (polly-neural, polly-generative, polly-standard).
func Speak(ctx context.Context, p PollyAPI, m Model, req SpeakRequest) (*Speech, error) {
	if m.Family != FamPolly {
		return nil, fmt.Errorf("%w: %s is not a speech model", ErrUnsupported, m.ID)
	}
	text := strings.TrimSpace(req.Text)
	if text == "" {
		return nil, BadInput("text is empty")
	}
	if n := len([]rune(text)); n > MaxSpeechChars {
		return nil, BadInput("text has %d characters; the limit is %d", n, MaxSpeechChars)
	}
	if req.Lang == "" {
		req.Lang = "es-US"
	}
	voice := req.Voice
	if voice == "" {
		voice = defaultVoices[req.Lang]
		if voice == "" {
			voice = "Joanna"
		}
	}
	format, ctype := pollytypes.OutputFormatMp3, "audio/mpeg"
	switch strings.ToLower(req.Format) {
	case "", "mp3":
	case "ogg", "ogg_vorbis":
		format, ctype = pollytypes.OutputFormatOggVorbis, "audio/ogg"
	case "pcm":
		format, ctype = pollytypes.OutputFormatPcm, "audio/L16;rate=16000"
	default:
		return nil, BadInput("format must be mp3, ogg or pcm")
	}
	engine := pollytypes.EngineNeural
	switch m.ID {
	case "polly-generative":
		engine = pollytypes.EngineGenerative
	case "polly-standard":
		engine = pollytypes.EngineStandard
	}
	var out bytes.Buffer
	chars := 0
	for _, chunk := range splitText(text, 2800) {
		body := chunk
		textType := pollytypes.TextTypeText
		if req.Rate != "" {
			textType = pollytypes.TextTypeSsml
			body = `<speak><prosody rate="` + escapeAttr(req.Rate) + `">` + escapeXML(chunk) + `</prosody></speak>`
		}
		in := &polly.SynthesizeSpeechInput{Text: aws.String(body), TextType: textType, VoiceId: pollytypes.VoiceId(voice), Engine: engine, OutputFormat: format}
		if format == pollytypes.OutputFormatPcm {
			in.SampleRate = aws.String("16000")
		}
		if req.Lang != "" {
			in.LanguageCode = pollytypes.LanguageCode(req.Lang)
		}
		o, err := p.SynthesizeSpeech(ctx, in)
		if err != nil {
			return nil, classifyPolly(err)
		}
		b, err := io.ReadAll(io.LimitReader(o.AudioStream, 64<<20))
		_ = o.AudioStream.Close()
		if err != nil {
			return nil, err
		}
		out.Write(b)
		chars += int(o.RequestCharacters)
	}
	f := string(format)
	if f == "ogg_vorbis" {
		f = "ogg"
	}
	return &Speech{Audio: out.Bytes(), ContentType: ctype, Format: f, Voice: voice, Chars: chars}, nil
}

func classifyPolly(err error) error {
	m := err.Error()
	if strings.Contains(m, "InvalidSsmlException") || strings.Contains(m, "ValidationException") || strings.Contains(m, "TextLengthExceeded") ||
		strings.Contains(m, "does not support the selected engine") || strings.Contains(m, "LanguageNotSupported") || strings.Contains(m, "InvalidParameter") {
		return fmt.Errorf("%w: %s", ErrBadInput, shorten(m))
	}
	return ClassifyAWS(err)
}

// ListVoices returns the Polly voices that support the engine of m, sorted by language and name.
type Voice struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Lang    string   `json:"lang"`
	Gender  string   `json:"gender"`
	Engines []string `json:"engines"`
}

func ListVoices(ctx context.Context, p PollyAPI, lang string) ([]Voice, error) {
	in := &polly.DescribeVoicesInput{IncludeAdditionalLanguageCodes: true}
	if lang != "" {
		in.LanguageCode = pollytypes.LanguageCode(lang)
	}
	o, err := p.DescribeVoices(ctx, in)
	if err != nil {
		return nil, classifyPolly(err)
	}
	var vs []Voice
	for _, v := range o.Voices {
		x := Voice{ID: string(v.Id), Name: aws.ToString(v.Name), Lang: string(v.LanguageCode), Gender: string(v.Gender)}
		for _, e := range v.SupportedEngines {
			x.Engines = append(x.Engines, string(e))
		}
		vs = append(vs, x)
	}
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Lang != vs[j].Lang {
			return vs[i].Lang < vs[j].Lang
		}
		return vs[i].Name < vs[j].Name
	})
	return vs, nil
}

// splitText cuts text into pieces of at most max runes, preferring sentence ends, then spaces.
func splitText(s string, max int) []string {
	r := []rune(s)
	if len(r) <= max {
		return []string{s}
	}
	var out []string
	for len(r) > 0 {
		if len(r) <= max {
			out = append(out, string(r))
			break
		}
		cut := -1
		for i := max; i > max/2; i-- {
			if strings.ContainsRune(".!?\n", r[i-1]) {
				cut = i
				break
			}
		}
		if cut < 0 {
			for i := max; i > max/2; i-- {
				if r[i-1] == ' ' {
					cut = i
					break
				}
			}
		}
		if cut < 0 {
			cut = max
		}
		out = append(out, strings.TrimSpace(string(r[:cut])))
		r = r[cut:]
	}
	return out
}

func escapeXML(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
func escapeAttr(s string) string {
	return strings.NewReplacer("\"", "", "<", "", ">", "", "&", "").Replace(s)
}

// ---------------------------------------------------------------- Transcribe (batch speech to text)

// TranscribeAPI is the Transcribe client surface in use.
type TranscribeAPI interface {
	StartTranscriptionJob(ctx context.Context, in *transcribe.StartTranscriptionJobInput, o ...func(*transcribe.Options)) (*transcribe.StartTranscriptionJobOutput, error)
	GetTranscriptionJob(ctx context.Context, in *transcribe.GetTranscriptionJobInput, o ...func(*transcribe.Options)) (*transcribe.GetTranscriptionJobOutput, error)
}

// Stage holds uploaded audio for Transcribe, which can only read from S3: a short-lived prefix of an existing bucket.
type Stage interface {
	Put(ctx context.Context, key string, data []byte, contentType string) (uri string, err error)
	Delete(ctx context.Context, key string) error
}

// JobStore persists job state (the platform cache, with a TTL).
type JobStore interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string, ttlSeconds int) error
}

// Segment is a stretch of speech with its time range.
type Segment struct {
	Start   float64 `json:"start"`
	End     float64 `json:"end"`
	Speaker string  `json:"speaker,omitempty"`
	Text    string  `json:"text"`
}

// Transcript is the normalized result.
type Transcript struct {
	Text     string    `json:"text"`
	Language string    `json:"language,omitempty"`
	Duration float64   `json:"duration_seconds"`
	Segments []Segment `json:"segments"`
	Speakers int       `json:"speakers,omitempty"`
}

// Job is an asynchronous transcription.
type Job struct {
	ID        string      `json:"id"`
	Kind      string      `json:"kind"`   // transcribe
	Status    string      `json:"status"` // queued | running | completed | failed
	Error     string      `json:"error,omitempty"`
	Language  string      `json:"language,omitempty"`
	Diarize   bool        `json:"diarize"`
	Bytes     int         `json:"bytes"`
	Result    *Transcript `json:"result,omitempty"`
	CostUSD   float64     `json:"cost_estimate_usd"`
	ProjectID string      `json:"project_id,omitempty"`
	UserID    string      `json:"user_id,omitempty"`
	CreatedAt time.Time   `json:"created_at"`
	StageKey  string      `json:"-"`
	Saved     string      `json:"saved_to,omitempty"` // bucket/key of the stored result
	SaveTo    string      `json:"-"`                  // bucket/key to store the rendered result in when the job completes
	SaveFmt   string      `json:"-"`
}

// Transcriber runs transcription jobs.
type Transcriber struct {
	API   TranscribeAPI
	Stage Stage
	Jobs  JobStore
	HTTP  *http.Client
	Now   func() time.Time
}

// MaxAudioBytes bounds an upload (Transcribe accepts 2 GB; the API request body is what limits us).
const MaxAudioBytes = 100 << 20

var audioFormats = map[string]trtypes.MediaFormat{"mp3": trtypes.MediaFormatMp3, "mp4": trtypes.MediaFormatMp4, "wav": trtypes.MediaFormatWav, "flac": trtypes.MediaFormatFlac,
	"ogg": trtypes.MediaFormatOgg, "amr": trtypes.MediaFormatAmr, "webm": trtypes.MediaFormatWebm, "m4a": trtypes.MediaFormatMp4}

// AudioFormat normalizes a file name or MIME type to a format Transcribe takes ("" when unknown).
func AudioFormat(nameOrMIME string) string {
	s := strings.ToLower(nameOrMIME)
	if i := strings.LastIndex(s, "."); i >= 0 && !strings.Contains(s, "/") {
		s = s[i+1:]
	}
	s = strings.TrimPrefix(s, "audio/")
	if i := strings.Index(s, ";"); i >= 0 {
		s = s[:i]
	}
	switch s {
	case "mpeg", "mpeg3", "x-mpeg-3":
		s = "mp3"
	case "x-wav", "wave", "vnd.wave":
		s = "wav"
	case "x-m4a", "m4a", "aac":
		s = "m4a"
	case "x-flac":
		s = "flac"
	case "video/webm":
		s = "webm"
	}
	if _, ok := audioFormats[s]; ok {
		return s
	}
	return ""
}

// StartRequest describes a transcription.
type StartRequest struct {
	Data        []byte
	Format      string
	Lang        string // es-US, en-US...; empty: identify the language
	Diarize     bool
	MaxSpeakers int
	ProjectID   string
	UserID      string
	SaveTo      string
	SaveFmt     string
	EstMinutes  float64 // from the caller (file size heuristic) for the price estimate
}

// Start uploads the audio and starts the job.
func (t *Transcriber) Start(ctx context.Context, req StartRequest) (*Job, error) {
	if len(req.Data) == 0 {
		return nil, BadInput("audio is empty")
	}
	if len(req.Data) > MaxAudioBytes {
		return nil, BadInput("audio is %d MB; the limit is %d MB", len(req.Data)>>20, MaxAudioBytes>>20)
	}
	mf, ok := audioFormats[req.Format]
	if !ok {
		return nil, BadInput("audio format %q not supported (mp3, mp4, m4a, wav, flac, ogg, amr, webm)", req.Format)
	}
	if req.MaxSpeakers < 0 || req.MaxSpeakers == 1 || req.MaxSpeakers > 30 {
		return nil, BadInput("max speakers must be between 2 and 30")
	}
	id := uuid.NewString()
	key := "ai-stage/" + id + "." + req.Format
	uri, err := t.Stage.Put(ctx, key, req.Data, "audio/"+req.Format)
	if err != nil {
		return nil, fmt.Errorf("staging audio: %w", err)
	}
	in := &transcribe.StartTranscriptionJobInput{
		TranscriptionJobName: aws.String("capsule-" + id),
		Media:                &trtypes.Media{MediaFileUri: aws.String(uri)},
		MediaFormat:          mf,
	}
	if req.Lang != "" {
		in.LanguageCode = trtypes.LanguageCode(req.Lang)
	} else {
		in.IdentifyLanguage = aws.Bool(true)
	}
	if req.Diarize {
		ms := req.MaxSpeakers
		if ms == 0 {
			ms = 5
		}
		in.Settings = &trtypes.Settings{ShowSpeakerLabels: aws.Bool(true), MaxSpeakerLabels: aws.Int32(int32(ms))}
	}
	if _, err := t.API.StartTranscriptionJob(ctx, in); err != nil {
		_ = t.Stage.Delete(ctx, key)
		return nil, classifyTranscribe(err)
	}
	mins := req.EstMinutes
	if mins <= 0 {
		mins = float64(len(req.Data)) / (16000 * 1.0) / 60 // ~128 kbit/s mp3 fallback
	}
	job := &Job{ID: id, Kind: "transcribe", Status: "queued", Language: req.Lang, Diarize: req.Diarize, Bytes: len(req.Data),
		CostUSD: roundUSD(mins * 0.024), ProjectID: req.ProjectID, UserID: req.UserID, SaveTo: req.SaveTo, SaveFmt: req.SaveFmt, CreatedAt: t.now(), StageKey: key}
	if err := t.save(ctx, job); err != nil {
		return nil, err
	}
	return job, nil
}

func (t *Transcriber) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func classifyTranscribe(err error) error {
	m := err.Error()
	if strings.Contains(m, "BadRequestException") || strings.Contains(m, "ConflictException") {
		return fmt.Errorf("%w: %s", ErrBadInput, shorten(m))
	}
	return ClassifyAWS(err)
}

func jobKey(id string) string { return "ai:job:" + id }

// Save persists the job (the handler updates Saved after storing the result).
func (t *Transcriber) Save(ctx context.Context, j *Job) error { return t.save(ctx, j) }

func (t *Transcriber) save(ctx context.Context, j *Job) error {
	b, err := json.Marshal(struct {
		Job
		StageKey string `json:"stage_key"`
		SaveTo   string `json:"save_to_target"`
		SaveFmt  string `json:"save_fmt"`
	}{*j, j.StageKey, j.SaveTo, j.SaveFmt})
	if err != nil {
		return err
	}
	return t.Jobs.Set(ctx, jobKey(j.ID), string(b), 7*24*3600)
}

// Load reads a job from the store.
func (t *Transcriber) Load(ctx context.Context, id string) (*Job, error) {
	s, err := t.Jobs.Get(ctx, jobKey(id))
	if err != nil || s == "" {
		return nil, ErrJobNotFound
	}
	var w struct {
		Job
		StageKey string `json:"stage_key"`
		SaveTo   string `json:"save_to_target"`
		SaveFmt  string `json:"save_fmt"`
	}
	if err := json.Unmarshal([]byte(s), &w); err != nil {
		return nil, ErrJobNotFound
	}
	j := w.Job
	j.StageKey, j.SaveTo, j.SaveFmt = w.StageKey, w.SaveTo, w.SaveFmt
	return &j, nil
}

// ErrJobNotFound means the id is unknown or expired.
var ErrJobNotFound = fmt.Errorf("job not found")

// Poll refreshes a job from Transcribe; on completion it downloads and normalizes the transcript and removes the staged audio.
func (t *Transcriber) Poll(ctx context.Context, j *Job) (*Job, error) {
	if j.Status == "completed" || j.Status == "failed" {
		return j, nil
	}
	o, err := t.API.GetTranscriptionJob(ctx, &transcribe.GetTranscriptionJobInput{TranscriptionJobName: aws.String("capsule-" + j.ID)})
	if err != nil {
		return nil, classifyTranscribe(err)
	}
	tj := o.TranscriptionJob
	switch tj.TranscriptionJobStatus {
	case trtypes.TranscriptionJobStatusQueued:
		j.Status = "queued"
	case trtypes.TranscriptionJobStatusInProgress:
		j.Status = "running"
	case trtypes.TranscriptionJobStatusFailed:
		j.Status, j.Error = "failed", aws.ToString(tj.FailureReason)
		t.cleanup(ctx, j)
	case trtypes.TranscriptionJobStatusCompleted:
		uri := ""
		if tj.Transcript != nil {
			uri = aws.ToString(tj.Transcript.TranscriptFileUri)
		}
		tr, err := t.fetch(ctx, uri)
		if err != nil {
			j.Status, j.Error = "failed", "reading the transcript: "+err.Error()
		} else {
			if tj.LanguageCode != "" {
				tr.Language = string(tj.LanguageCode)
			}
			j.Status, j.Result, j.Language = "completed", tr, tr.Language
			if tr.Duration > 0 {
				j.CostUSD = roundUSD(tr.Duration / 60 * 0.024)
			}
		}
		t.cleanup(ctx, j)
	}
	if err := t.save(ctx, j); err != nil {
		return nil, err
	}
	return j, nil
}

func (t *Transcriber) cleanup(ctx context.Context, j *Job) {
	if j.StageKey != "" {
		_ = t.Stage.Delete(ctx, j.StageKey)
		j.StageKey = ""
	}
}

func (t *Transcriber) fetch(ctx context.Context, uri string) (*Transcript, error) {
	if !strings.HasPrefix(uri, "https://") {
		return nil, fmt.Errorf("no transcript uri")
	}
	hc := t.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	rq, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(rq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("transcript download answered %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	return ParseAWSTranscript(b)
}

// ParseAWSTranscript converts Amazon Transcribe's output JSON into a Transcript: sentences with start/end time and speaker label.
func ParseAWSTranscript(b []byte) (*Transcript, error) {
	var raw struct {
		Results struct {
			Transcripts []struct {
				Transcript string `json:"transcript"`
			} `json:"transcripts"`
			Items []struct {
				Type         string `json:"type"`
				Start        string `json:"start_time"`
				End          string `json:"end_time"`
				Speaker      string `json:"speaker_label"`
				Alternatives []struct {
					Content string `json:"content"`
				} `json:"alternatives"`
			} `json:"items"`
		} `json:"results"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("invalid transcript JSON")
	}
	tr := &Transcript{}
	if len(raw.Results.Transcripts) > 0 {
		tr.Text = raw.Results.Transcripts[0].Transcript
	}
	var cur *Segment
	words := 0
	flush := func() {
		if cur != nil && strings.TrimSpace(cur.Text) != "" {
			cur.Text = strings.TrimSpace(cur.Text)
			tr.Segments = append(tr.Segments, *cur)
		}
		cur, words = nil, 0
	}
	speakers := map[string]bool{}
	for _, it := range raw.Results.Items {
		if len(it.Alternatives) == 0 {
			continue
		}
		w := it.Alternatives[0].Content
		if it.Type == "punctuation" {
			if cur != nil {
				cur.Text += w
				if w == "." || w == "?" || w == "!" || w == "。" {
					flush()
				}
			}
			continue
		}
		st, _ := strconv.ParseFloat(it.Start, 64)
		en, _ := strconv.ParseFloat(it.End, 64)
		if it.Speaker != "" {
			speakers[it.Speaker] = true
		}
		if cur != nil && (cur.Speaker != it.Speaker || words >= 40 || st-cur.End > 2.0) {
			flush()
		}
		if cur == nil {
			cur = &Segment{Start: st, Speaker: it.Speaker}
		}
		if cur.Text != "" {
			cur.Text += " "
		}
		cur.Text += w
		cur.End = en
		words++
		if en > tr.Duration {
			tr.Duration = en
		}
	}
	flush()
	if tr.Text == "" {
		var parts []string
		for _, s := range tr.Segments {
			parts = append(parts, s.Text)
		}
		tr.Text = strings.Join(parts, " ")
	}
	tr.Speakers = len(speakers)
	return tr, nil
}

// Render formats a transcript as txt, srt, vtt or json.
func (tr *Transcript) Render(format string) ([]byte, string, error) {
	switch strings.ToLower(format) {
	case "", "txt", "text":
		var b strings.Builder
		prev := "\x00"
		for _, s := range tr.Segments {
			if s.Speaker != "" && s.Speaker != prev {
				if b.Len() > 0 {
					cur := strings.TrimRight(b.String(), " ")
					b.Reset()
					b.WriteString(cur + "\n")
				}
				b.WriteString(speakerName(s.Speaker) + ": ")
			}
			prev = s.Speaker
			b.WriteString(s.Text + " ")
		}
		out := strings.TrimSpace(b.String())
		if out == "" {
			out = tr.Text
		}
		return []byte(out + "\n"), "text/plain; charset=utf-8", nil
	case "srt":
		var b strings.Builder
		for i, s := range tr.Segments {
			fmt.Fprintf(&b, "%d\n%s --> %s\n%s%s\n\n", i+1, stamp(s.Start, ','), stamp(s.End, ','), spk(s), s.Text)
		}
		return []byte(b.String()), "application/x-subrip; charset=utf-8", nil
	case "vtt":
		var b strings.Builder
		b.WriteString("WEBVTT\n\n")
		for _, s := range tr.Segments {
			fmt.Fprintf(&b, "%s --> %s\n%s%s\n\n", stamp(s.Start, '.'), stamp(s.End, '.'), spk(s), s.Text)
		}
		return []byte(b.String()), "text/vtt; charset=utf-8", nil
	case "json":
		b, err := json.MarshalIndent(tr, "", "  ")
		return append(b, '\n'), "application/json", err
	}
	return nil, "", BadInput("format must be txt, srt, vtt or json")
}

func speakerName(l string) string {
	if strings.HasPrefix(l, "spk_") {
		if n, err := strconv.Atoi(l[4:]); err == nil {
			return "Speaker " + strconv.Itoa(n+1)
		}
	}
	return l
}

func spk(s Segment) string {
	if s.Speaker == "" {
		return ""
	}
	return speakerName(s.Speaker) + ": "
}

func stamp(sec float64, sep byte) string {
	ms := int(sec*1000 + 0.5)
	return fmt.Sprintf("%02d:%02d:%02d%c%03d", ms/3600000, ms/60000%60, ms/1000%60, sep, ms%1000)
}

func roundUSD(v float64) float64 { return math.Round(v*1e8) / 1e8 }
