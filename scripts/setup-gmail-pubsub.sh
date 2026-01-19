#!/bin/bash
# Gmail Push Notifications Setup Script
# Run this in your terminal: ./scripts/setup-gmail-pubsub.sh

set -e

PROJECT_ID="swordfish-483305"
TOPIC_NAME="gmail-notifications"
SUBSCRIPTION_NAME="gmail-push-subscription"
WEBHOOK_URL="https://swordfish-eight.vercel.app/api/webhooks/gmail"

echo "🔐 Step 1: Authenticating with Google Cloud..."
gcloud auth login

echo ""
echo "📧 Step 2: Creating Pub/Sub topic..."
gcloud pubsub topics create $TOPIC_NAME --project=$PROJECT_ID 2>/dev/null || echo "Topic already exists, continuing..."

echo ""
echo "🔑 Step 3: Granting Gmail API publish permission..."
gcloud pubsub topics add-iam-policy-binding $TOPIC_NAME \
  --member="serviceAccount:gmail-api-push@system.gserviceaccount.com" \
  --role="roles/pubsub.publisher" \
  --project=$PROJECT_ID

echo ""
echo "🔗 Step 4: Creating push subscription to webhook..."
gcloud pubsub subscriptions create $SUBSCRIPTION_NAME \
  --topic=$TOPIC_NAME \
  --push-endpoint=$WEBHOOK_URL \
  --ack-deadline=60 \
  --project=$PROJECT_ID 2>/dev/null || echo "Subscription already exists, continuing..."

echo ""
echo "✅ Setup complete!"
echo ""
echo "Topic name for Vercel env: projects/$PROJECT_ID/topics/$TOPIC_NAME"
echo ""
echo "Next steps:"
echo "1. Reconnect your Gmail integration in Swordfish dashboard"
echo "2. New emails will be detected in real-time!"
