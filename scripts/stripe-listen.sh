#!/bin/bash
# Start Stripe webhook listener
# Forwards events to local dev server

STRIPE_KEY=$(cat ~/.stripe_key 2>/dev/null)
if [ -z "$STRIPE_KEY" ]; then
  echo "Error: No Stripe key found at ~/.stripe_key"
  exit 1
fi

~/bin/stripe listen \
  --api-key "$STRIPE_KEY" \
  --forward-to http://localhost:3000/api/webhooks/stripe \
  "$@"
