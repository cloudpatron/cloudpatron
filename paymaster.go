package main

import (
	"time"

	stripe "github.com/stripe/stripe-go"
	stripecharge "github.com/stripe/stripe-go/charge"
)

var (
	paymasterInterval    = 6 * time.Hour
	paymasterDaystart    = 1 // The first of the month.
	paymasterDayend      = 5 // The fifth of the month.
	paymasterMaxAttempts = 5 // How many attempts to charge per payment.
)

func paymaster() {
	for {
		time.Sleep(paymasterInterval)

		now := time.Now()
		day := now.Day()
		month := now.Month()
		year := now.Year()

		if day < paymasterDaystart || day > paymasterDayend {
			continue
		}
		logger.Infof("paymaster running %s", now)

		// Create payments
		for _, patron := range database.ListActivePatrons() {
			due := true
			for _, payment := range database.ListPaymentsByPatron(patron.ID) {
				if payment.Created.Month() == month && payment.Created.Year() == year {
					due = false
				}
			}

			if due {
				newpayment, err := database.AddPayment(patron.ID, patron.Amount)
				if err != nil {
					logger.Error(err)
					continue
				}
				logger.Infof("paymaster> creating payment for %s $%d", newpayment.PatronID, newpayment.Amount)
			}
		}

		// Charge payments
		for _, payment := range database.ListPayments() {
			if payment.Created.Month() != month || payment.Created.Year() != year {
				continue
			}
			if payment.Paid {
				continue
			}
			if payment.Attempts >= paymasterMaxAttempts {
				continue
			}
			if payment.Patron.Stripe == "" {
				continue
			}
			logger.Infof("paymaster> attempting to charge %s $%d", payment.PatronID, payment.Amount)
			database.UpdatePayment(payment.ID, func(p *Payment) error {
				p.Attempts += 1
				return nil
			})

			params := &stripe.ChargeParams{
				Amount:   stripe.Int64(int64(payment.Amount * 100)),
				Currency: stripe.String(string(stripe.CurrencyUSD)),
				Customer: stripe.String(payment.Patron.Stripe),
			}

			charge, err := stripecharge.New(params)
			if err != nil {
				logger.Error(err)
				continue
			}
			logger.Infof("paymaster> successfully charged %s $%d (%s)", payment.PatronID, payment.Amount, charge.ID)
			database.UpdatePayment(payment.ID, func(p *Payment) error {
				p.Paid = true
				return nil
			})
		}
	}
}
