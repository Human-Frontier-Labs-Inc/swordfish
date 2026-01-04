#!/bin/bash

# ============================================================================
# SWORDFISH - Quick Setup (Minimum Viable)
# ============================================================================
# Sets up only the essential services needed to run the app locally:
# - Neon (Database)
# - Upstash Redis (Cache)
# - Encryption keys
#
# Usage: ./scripts/setup-quick.sh
# ============================================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          SWORDFISH QUICK SETUP (MVP)                           ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check and install CLI tools
echo -e "${YELLOW}► Installing required CLI tools...${NC}"

if ! command -v neonctl &> /dev/null; then
    npm install -g neonctl
fi

if ! command -v upstash &> /dev/null; then
    npm install -g @upstash/cli
fi

echo -e "${GREEN}✓ CLI tools ready${NC}"
echo ""

# Generate encryption keys first
echo -e "${YELLOW}► Generating encryption keys...${NC}"
ENCRYPTION_KEY=$(openssl rand -base64 32)
ENCRYPTION_SALT=$(openssl rand -base64 16)
echo -e "${GREEN}✓ Keys generated${NC}"
echo ""

# Create output
OUTPUT_FILE=".env.quickstart"
cat > "$OUTPUT_FILE" << EOF
# Swordfish Quick Setup - Generated $(date)
# Copy these to your .env.local

# App
NODE_ENV=development
NEXT_PUBLIC_APP_URL=http://localhost:3000
NEXT_PUBLIC_APP_NAME=Swordfish

# Encryption (auto-generated)
ENCRYPTION_KEY=$ENCRYPTION_KEY
ENCRYPTION_SALT=$ENCRYPTION_SALT

# Development mode - skip external APIs
MOCK_EXTERNAL_APIS=true

EOF

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}STEP 1: Neon Database${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Running: neonctl auth (will open browser)"
read -p "Press Enter to continue..."

neonctl auth

echo ""
echo "Creating project..."
PROJECT_ID=$(neonctl projects create --name swordfish --output json 2>/dev/null | jq -r '.project.id' || echo "")

if [ -n "$PROJECT_ID" ]; then
    CONNECTION_STRING=$(neonctl connection-string --project-id "$PROJECT_ID" 2>/dev/null)
    echo "DATABASE_URL=$CONNECTION_STRING" >> "$OUTPUT_FILE"
    echo -e "${GREEN}✓ Neon database created${NC}"
else
    echo -e "${YELLOW}⚠ Could not auto-create. Get connection string from https://console.neon.tech${NC}"
    echo "DATABASE_URL=" >> "$OUTPUT_FILE"
fi

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}STEP 2: Upstash Redis${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Get your API key from: https://console.upstash.com/account/api"
read -p "Press Enter when ready to login..."

upstash auth login

echo ""
echo "Creating Redis database..."
REDIS_OUTPUT=$(upstash redis create --name=swordfish-cache --region=us-east-1 2>/dev/null || echo "exists")

if [ "$REDIS_OUTPUT" != "exists" ]; then
    echo -e "${GREEN}✓ Redis created${NC}"
fi

echo ""
echo -e "${YELLOW}Get Redis credentials from: https://console.upstash.com${NC}"
echo "UPSTASH_REDIS_REST_URL=" >> "$OUTPUT_FILE"
echo "UPSTASH_REDIS_REST_TOKEN=" >> "$OUTPUT_FILE"

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}STEP 3: Clerk (Manual - Required)${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "1. Go to: https://dashboard.clerk.com"
echo "2. Create a new application"
echo "3. Copy your keys"
echo ""

cat >> "$OUTPUT_FILE" << 'EOF'

# Clerk - Get from https://dashboard.clerk.com
CLERK_SECRET_KEY=
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=
NEXT_PUBLIC_CLERK_SIGN_IN_URL=/sign-in
NEXT_PUBLIC_CLERK_SIGN_UP_URL=/sign-up
NEXT_PUBLIC_CLERK_SIGN_IN_FORCE_REDIRECT_URL=/dashboard
NEXT_PUBLIC_CLERK_SIGN_UP_FORCE_REDIRECT_URL=/dashboard
EOF

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}SETUP COMPLETE!${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Generated file: $OUTPUT_FILE"
echo ""
echo "Next steps:"
echo "  1. Fill in missing values in $OUTPUT_FILE"
echo "  2. Copy to .env.local: cp $OUTPUT_FILE .env.local"
echo "  3. Run: npm run dev"
echo ""
echo "To see generated content:"
echo "  cat $OUTPUT_FILE"
echo ""
