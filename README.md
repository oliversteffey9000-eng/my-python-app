# MacroTracker

MacroTracker is a publishable web app/PWA for calorie and macro tracking with:

- Required first-run onboarding with email, name, and date of birth
- White/blue light mode and black/blue dark mode
- Real food cards with photos
- Daily calories and macro tracking
- Barcode logging with manual fallback
- Nutrition label photo scanning
- Homemade recipe photo scanning
- Manual custom foods and correction editing when data is wrong
- Premium plans: `$5/month` and `$25/year`
- Stripe Checkout subscriptions
- Premium-gated AI food photo scan
- Complaint and bug report form

## Run in Visual Studio Code

1. Open this folder in VS Code.
2. Open the terminal.
3. Run:

```powershell
python app.py
```

4. Open:

```text
http://127.0.0.1:8000
```

## Stripe Setup

Create two recurring Stripe Prices:

- Monthly: `$5/month`
- Yearly: `$25/year`

Set these environment variables before running:

```powershell
$env:STRIPE_SECRET_KEY="sk_live_or_test_key"
$env:STRIPE_MONTHLY_PRICE_ID="price_monthly_id"
$env:STRIPE_YEARLY_PRICE_ID="price_yearly_id"
$env:STRIPE_WEBHOOK_SECRET="whsec_webhook_secret"
$env:BASE_URL="https://your-domain.com"
$env:OPENAI_API_KEY="sk-your-openai-key"
python app.py
```

In Stripe, add this webhook endpoint:

```text
https://your-domain.com/api/stripe-webhook
```

Listen for:

- `checkout.session.completed`
- `customer.subscription.deleted`
- `customer.subscription.paused`

## Publishing

For a website, deploy this Python app to a host that supports long-running web apps, such as Render, Railway, Fly.io, or a VPS. Set the same environment variables in your hosting dashboard.

For app stores, wrap the hosted web app with Capacitor after it is live. Keep Stripe and OpenAI keys on this server, never in the mobile app JavaScript.

## Notes

This app uses Stripe Checkout. Users enter card details on Stripe's secure hosted page, not inside MacroTracker.
