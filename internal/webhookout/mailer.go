package webhookout

import (
	"context"
	"errors"
	"net/mail"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sestypes "github.com/aws/aws-sdk-go-v2/service/sesv2/types"

	"github.com/kynto/capsule/backend/internal/gitevents"
)

// SESAPI is the part of *sesv2.Client the mailer uses (a fake in tests).
type SESAPI interface {
	SendEmail(ctx context.Context, in *sesv2.SendEmailInput, opts ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error)
}

// SESMailer sends notification and webhook emails through Amazon SES. The sender address must be
// a verified SES identity (CAPSULE_NOTIFY_FROM_EMAIL).
type SESMailer struct {
	Client SESAPI
	From   string
}

var _ gitevents.Mailer = (*SESMailer)(nil)

// MailerFromEnv builds the mailer from CAPSULE_NOTIFY_FROM_EMAIL. It returns nil (email channel
// off, with a clear delivery error) when SES is not available or the variable is empty or invalid.
func MailerFromEnv(client SESAPI) gitevents.Mailer {
	from := strings.TrimSpace(os.Getenv("CAPSULE_NOTIFY_FROM_EMAIL"))
	if client == nil || from == "" {
		return nil
	}
	if _, err := mail.ParseAddress(from); err != nil {
		return nil
	}
	return &SESMailer{Client: client, From: from}
}

// Send implements gitevents.Mailer. Header injection is impossible: addresses are parsed and the
// subject has no control characters (SES also takes them as structured fields, not raw headers).
func (m *SESMailer) Send(ctx context.Context, to []string, subject, text, html string) error {
	if len(to) == 0 {
		return errors.New("no recipients")
	}
	for _, a := range to {
		p, err := mail.ParseAddress(a)
		if err != nil || p.Address != a || strings.ContainsAny(a, "\r\n") {
			return errors.New("invalid recipient address")
		}
	}
	subject = strings.Join(strings.Fields(subject), " ")
	body := &sestypes.Body{Text: &sestypes.Content{Data: aws.String(text), Charset: aws.String("UTF-8")}}
	if html != "" {
		body.Html = &sestypes.Content{Data: aws.String(html), Charset: aws.String("UTF-8")}
	}
	_, err := m.Client.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(m.From),
		Destination:      &sestypes.Destination{ToAddresses: to},
		Content: &sestypes.EmailContent{Simple: &sestypes.Message{
			Subject: &sestypes.Content{Data: aws.String(subject), Charset: aws.String("UTF-8")},
			Body:    body,
		}},
	})
	if err != nil {
		return errors.New("SES rejected the message")
	}
	return nil
}
