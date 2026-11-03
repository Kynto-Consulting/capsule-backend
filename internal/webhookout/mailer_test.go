package webhookout

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sesv2"
)

type fakeSES struct {
	in  *sesv2.SendEmailInput
	err error
}

func (f *fakeSES) SendEmail(_ context.Context, in *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
	f.in = in
	return &sesv2.SendEmailOutput{}, f.err
}

func TestMailerFromEnv(t *testing.T) {
	t.Setenv("CAPSULE_NOTIFY_FROM_EMAIL", "")
	if MailerFromEnv(&fakeSES{}) != nil {
		t.Fatal("no sender configured -> no mailer")
	}
	t.Setenv("CAPSULE_NOTIFY_FROM_EMAIL", "not an address")
	if MailerFromEnv(&fakeSES{}) != nil {
		t.Fatal("invalid sender -> no mailer")
	}
	t.Setenv("CAPSULE_NOTIFY_FROM_EMAIL", "notificaciones@example.com")
	if MailerFromEnv(nil) != nil {
		t.Fatal("no SES client -> no mailer")
	}
	if MailerFromEnv(&fakeSES{}) == nil {
		t.Fatal("configured mailer expected")
	}
}

func TestSESMailerSend(t *testing.T) {
	ses := &fakeSES{}
	m := &SESMailer{Client: ses, From: "notificaciones@example.com"}
	if err := m.Send(context.Background(), []string{"a@x.io"}, "Hola\r\nBcc: e@x.io", "texto", "<p>html</p>"); err != nil {
		t.Fatal(err)
	}
	if *ses.in.FromEmailAddress != "notificaciones@example.com" || ses.in.Destination.ToAddresses[0] != "a@x.io" {
		t.Fatalf("%+v", ses.in)
	}
	if subj := *ses.in.Content.Simple.Subject.Data; strings.ContainsAny(subj, "\r\n") {
		t.Fatalf("subject must be one line: %q", subj)
	}
	if ses.in.Content.Simple.Body.Html == nil || ses.in.Content.Simple.Body.Text == nil {
		t.Fatal("both text and html bodies expected")
	}
	for _, bad := range []string{"a@x.io\r\nBcc: e@x.io", "Eve <e@x.io>", "nope"} {
		if err := m.Send(context.Background(), []string{bad}, "s", "t", ""); err == nil {
			t.Errorf("recipient %q must be rejected", bad)
		}
	}
	if err := m.Send(context.Background(), nil, "s", "t", ""); err == nil {
		t.Error("no recipients")
	}
	ses.err = errors.New("AccessDenied arn:aws:iam::1:user/x")
	if err := m.Send(context.Background(), []string{"a@x.io"}, "s", "t", ""); err == nil || strings.Contains(err.Error(), "arn:") {
		t.Fatalf("SES errors are not passed through: %v", err)
	}
}
