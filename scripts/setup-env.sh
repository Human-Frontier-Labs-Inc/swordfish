#!/bin/bash

# ============================================================================
# SWORDFISH - Automated Environment Setup Script
# ============================================================================
# This script automates the setup of CLI-based services and generates
# environment variables for your .env.local file
#
# Usage: ./scripts/setup-env.sh [options]
# Options:
#   --all           Run all setup steps
#   --neon          Setup Neon PostgreSQL only
#   --upstash       Setup Upstash Redis & Kafka only
#   --cloudflare    Setup Cloudflare R2 & Workers only
#   --azure         Setup Azure AD app registration only
#   --virustotal    Setup VirusTotal CLI only
#   --urlscan       Setup URLScan.io CLI only
#   --keys          Generate encryption keys only
#   --help          Show this help message
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Project configuration
PROJECT_NAME="swordfish"
REGION="us-east-1"

# Output file for generated env vars
ENV_OUTPUT_FILE=".env.generated"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

print_header() {
    echo ""
    echo -e "${PURPLE}============================================================================${NC}"
    echo -e "${PURPLE}  $1${NC}"
    echo -e "${PURPLE}============================================================================${NC}"
    echo ""
}

print_step() {
    echo -e "${CYAN}► $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_env() {
    echo -e "${BLUE}  $1${NC}"
}

add_env_var() {
    local key=$1
    local value=$2
    echo "$key=$value" >> "$ENV_OUTPUT_FILE"
    print_env "$key=$value"
}

check_command() {
    if command -v "$1" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

confirm() {
    read -p "$(echo -e ${YELLOW}"$1 [y/N]: "${NC})" response
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

# ============================================================================
# DEPENDENCY CHECKS & INSTALLATION
# ============================================================================

check_dependencies() {
    print_header "Checking Dependencies"

    local missing_deps=()

    # Check for Homebrew (macOS)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if ! check_command brew; then
            print_warning "Homebrew not found. Installing..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        else
            print_success "Homebrew installed"
        fi
    fi

    # Check for Node.js
    if ! check_command node; then
        missing_deps+=("node")
        print_error "Node.js not found"
    else
        print_success "Node.js $(node --version) installed"
    fi

    # Check for npm
    if ! check_command npm; then
        missing_deps+=("npm")
        print_error "npm not found"
    else
        print_success "npm $(npm --version) installed"
    fi

    # Check for Python (for Joe Sandbox)
    if ! check_command python3; then
        print_warning "Python3 not found (optional, for Joe Sandbox CLI)"
    else
        print_success "Python $(python3 --version) installed"
    fi

    # Check for jq (for JSON parsing)
    if ! check_command jq; then
        print_warning "jq not found. Installing..."
        if [[ "$OSTYPE" == "darwin"* ]]; then
            brew install jq
        else
            sudo apt-get install -y jq 2>/dev/null || sudo yum install -y jq 2>/dev/null
        fi
    else
        print_success "jq installed"
    fi

    if [ ${#missing_deps[@]} -gt 0 ]; then
        print_error "Missing required dependencies: ${missing_deps[*]}"
        print_error "Please install them and run this script again."
        exit 1
    fi

    echo ""
    print_success "All required dependencies are installed!"
}

install_cli_tools() {
    print_header "Installing CLI Tools"

    # Neon CLI
    print_step "Installing Neon CLI..."
    if ! check_command neonctl; then
        npm install -g neonctl
        print_success "Neon CLI installed"
    else
        print_success "Neon CLI already installed"
    fi

    # Upstash CLI
    print_step "Installing Upstash CLI..."
    if ! check_command upstash; then
        npm install -g @upstash/cli
        print_success "Upstash CLI installed"
    else
        print_success "Upstash CLI already installed"
    fi

    # Wrangler (Cloudflare)
    print_step "Installing Cloudflare Wrangler..."
    if ! check_command wrangler; then
        npm install -g wrangler
        print_success "Wrangler installed"
    else
        print_success "Wrangler already installed"
    fi

    # Azure CLI
    print_step "Checking Azure CLI..."
    if ! check_command az; then
        print_warning "Azure CLI not found. Installing..."
        if [[ "$OSTYPE" == "darwin"* ]]; then
            brew install azure-cli
        else
            curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
        fi
        print_success "Azure CLI installed"
    else
        print_success "Azure CLI already installed"
    fi

    # VirusTotal CLI
    print_step "Checking VirusTotal CLI..."
    if ! check_command vt; then
        print_warning "VirusTotal CLI not found. Installing..."
        if [[ "$OSTYPE" == "darwin"* ]]; then
            brew install virustotal-cli
        else
            # Download from GitHub releases for Linux
            VT_VERSION=$(curl -s https://api.github.com/repos/VirusTotal/vt-cli/releases/latest | jq -r '.tag_name')
            curl -LO "https://github.com/VirusTotal/vt-cli/releases/download/${VT_VERSION}/vt_${VT_VERSION#v}_linux_amd64.tar.gz"
            tar -xzf "vt_${VT_VERSION#v}_linux_amd64.tar.gz"
            sudo mv vt /usr/local/bin/
            rm "vt_${VT_VERSION#v}_linux_amd64.tar.gz"
        fi
        print_success "VirusTotal CLI installed"
    else
        print_success "VirusTotal CLI already installed"
    fi

    # URLScan CLI
    print_step "Checking URLScan CLI..."
    if ! check_command urlscan; then
        print_warning "URLScan CLI not found. Installing..."
        if [[ "$OSTYPE" == "darwin"* ]]; then
            brew install urlscan/tap/urlscan-cli
        else
            print_warning "URLScan CLI requires manual installation on Linux"
            print_warning "Visit: https://urlscan.io/blog/2025/09/02/cli-announcement/"
        fi
    else
        print_success "URLScan CLI already installed"
    fi

    # Joe Sandbox (Python)
    print_step "Checking Joe Sandbox CLI..."
    if ! python3 -c "import jbxapi" 2>/dev/null; then
        print_warning "Joe Sandbox CLI not found. Installing..."
        pip3 install jbxapi
        print_success "Joe Sandbox CLI installed"
    else
        print_success "Joe Sandbox CLI already installed"
    fi
}

# ============================================================================
# SERVICE SETUP FUNCTIONS
# ============================================================================

setup_neon() {
    print_header "Setting Up Neon PostgreSQL"

    print_step "Authenticating with Neon..."
    echo "This will open a browser window for OAuth authentication."
    if confirm "Continue with Neon authentication?"; then
        neonctl auth

        print_step "Creating Neon project..."
        # Check if project already exists
        EXISTING_PROJECT=$(neonctl projects list --output json 2>/dev/null | jq -r ".[] | select(.name == \"$PROJECT_NAME\") | .id" || echo "")

        if [ -n "$EXISTING_PROJECT" ]; then
            print_warning "Project '$PROJECT_NAME' already exists (ID: $EXISTING_PROJECT)"
            PROJECT_ID=$EXISTING_PROJECT
        else
            PROJECT_OUTPUT=$(neonctl projects create --name "$PROJECT_NAME" --output json)
            PROJECT_ID=$(echo "$PROJECT_OUTPUT" | jq -r '.project.id')
            print_success "Created project: $PROJECT_ID"
        fi

        print_step "Getting connection string..."
        CONNECTION_STRING=$(neonctl connection-string --project-id "$PROJECT_ID" 2>/dev/null || echo "")

        if [ -n "$CONNECTION_STRING" ]; then
            echo ""
            print_success "Neon setup complete!"
            add_env_var "DATABASE_URL" "$CONNECTION_STRING"
        else
            print_error "Could not retrieve connection string. Please check Neon dashboard."
        fi
    else
        print_warning "Skipping Neon setup"
    fi
}

setup_upstash() {
    print_header "Setting Up Upstash Redis & Kafka"

    print_step "Authenticating with Upstash..."
    echo "You'll need your Upstash email and API key from: https://console.upstash.com/account/api"

    if confirm "Continue with Upstash authentication?"; then
        upstash auth login

        # Create Redis database
        print_step "Creating Redis database..."
        REDIS_EXISTS=$(upstash redis list 2>/dev/null | grep -c "${PROJECT_NAME}-cache" || echo "0")

        if [ "$REDIS_EXISTS" -gt 0 ]; then
            print_warning "Redis database '${PROJECT_NAME}-cache' already exists"
            REDIS_OUTPUT=$(upstash redis list --json 2>/dev/null | jq -r ".[] | select(.name == \"${PROJECT_NAME}-cache\")")
        else
            REDIS_OUTPUT=$(upstash redis create --name="${PROJECT_NAME}-cache" --region=us-east-1 --json 2>/dev/null || echo "")
            print_success "Created Redis database"
        fi

        if [ -n "$REDIS_OUTPUT" ]; then
            REDIS_URL=$(echo "$REDIS_OUTPUT" | jq -r '.endpoint // .rest_url // empty' 2>/dev/null || echo "")
            REDIS_TOKEN=$(echo "$REDIS_OUTPUT" | jq -r '.rest_token // .password // empty' 2>/dev/null || echo "")

            if [ -n "$REDIS_URL" ]; then
                add_env_var "UPSTASH_REDIS_REST_URL" "https://$REDIS_URL"
                add_env_var "UPSTASH_REDIS_REST_TOKEN" "$REDIS_TOKEN"
            fi
        fi

        # Create Kafka cluster
        print_step "Creating Kafka cluster..."
        if confirm "Create Kafka cluster? (Optional, for async processing)"; then
            KAFKA_OUTPUT=$(upstash kafka create --name="${PROJECT_NAME}-queue" --region=us-east-1 --json 2>/dev/null || echo "")

            if [ -n "$KAFKA_OUTPUT" ]; then
                KAFKA_URL=$(echo "$KAFKA_OUTPUT" | jq -r '.endpoint // empty' 2>/dev/null || echo "")
                KAFKA_USER=$(echo "$KAFKA_OUTPUT" | jq -r '.username // empty' 2>/dev/null || echo "")
                KAFKA_PASS=$(echo "$KAFKA_OUTPUT" | jq -r '.password // empty' 2>/dev/null || echo "")

                if [ -n "$KAFKA_URL" ]; then
                    add_env_var "UPSTASH_KAFKA_REST_URL" "https://$KAFKA_URL"
                    add_env_var "UPSTASH_KAFKA_REST_USERNAME" "$KAFKA_USER"
                    add_env_var "UPSTASH_KAFKA_REST_PASSWORD" "$KAFKA_PASS"
                fi

                print_success "Created Kafka cluster"
            fi
        fi

        echo ""
        print_success "Upstash setup complete!"
    else
        print_warning "Skipping Upstash setup"
    fi
}

setup_cloudflare() {
    print_header "Setting Up Cloudflare R2 & Workers"

    print_step "Authenticating with Cloudflare..."
    echo "This will open a browser window for OAuth authentication."

    if confirm "Continue with Cloudflare authentication?"; then
        wrangler login

        # Get account info
        print_step "Getting account information..."
        ACCOUNT_INFO=$(wrangler whoami 2>/dev/null || echo "")
        ACCOUNT_ID=$(echo "$ACCOUNT_INFO" | grep -oE '[a-f0-9]{32}' | head -1 || echo "")

        if [ -n "$ACCOUNT_ID" ]; then
            add_env_var "CLOUDFLARE_ACCOUNT_ID" "$ACCOUNT_ID"
        fi

        # Create R2 bucket
        print_step "Creating R2 bucket..."
        BUCKET_NAME="${PROJECT_NAME}-artifacts"

        if wrangler r2 bucket list 2>/dev/null | grep -q "$BUCKET_NAME"; then
            print_warning "R2 bucket '$BUCKET_NAME' already exists"
        else
            wrangler r2 bucket create "$BUCKET_NAME"
            print_success "Created R2 bucket: $BUCKET_NAME"
        fi

        add_env_var "CLOUDFLARE_R2_BUCKET_NAME" "$BUCKET_NAME"

        # Note about API tokens
        echo ""
        print_warning "For R2 API access, you need to create an API token manually:"
        echo "  1. Go to: https://dash.cloudflare.com/profile/api-tokens"
        echo "  2. Create token with 'R2 Read & Write' permissions"
        echo "  3. Add CLOUDFLARE_R2_ACCESS_KEY_ID and CLOUDFLARE_R2_SECRET_ACCESS_KEY to .env.local"

        echo ""
        print_success "Cloudflare setup complete!"
    else
        print_warning "Skipping Cloudflare setup"
    fi
}

setup_azure() {
    print_header "Setting Up Azure AD App Registration"

    print_step "Authenticating with Azure..."
    echo "This will open a browser window for authentication."

    if confirm "Continue with Azure authentication?"; then
        az login

        print_step "Creating app registration..."
        APP_NAME="Swordfish Email Security"
        REDIRECT_URI="http://localhost:3000/api/integrations/o365/callback"

        # Check if app exists
        EXISTING_APP=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv 2>/dev/null || echo "")

        if [ -n "$EXISTING_APP" ]; then
            print_warning "App '$APP_NAME' already exists (ID: $EXISTING_APP)"
            APP_ID=$EXISTING_APP
        else
            # Create the app registration
            APP_OUTPUT=$(az ad app create \
                --display-name "$APP_NAME" \
                --web-redirect-uris "$REDIRECT_URI" \
                --query "appId" -o tsv)
            APP_ID=$APP_OUTPUT
            print_success "Created app registration: $APP_ID"
        fi

        add_env_var "MICROSOFT_CLIENT_ID" "$APP_ID"
        add_env_var "MICROSOFT_REDIRECT_URI" "$REDIRECT_URI"
        add_env_var "MICROSOFT_TENANT_ID" "common"

        # Create client secret
        print_step "Creating client secret..."
        if confirm "Generate a new client secret?"; then
            SECRET_OUTPUT=$(az ad app credential reset \
                --id "$APP_ID" \
                --display-name "swordfish-secret" \
                --years 2 \
                --query "password" -o tsv 2>/dev/null || echo "")

            if [ -n "$SECRET_OUTPUT" ]; then
                add_env_var "MICROSOFT_CLIENT_SECRET" "$SECRET_OUTPUT"
                print_success "Created client secret (save this - it won't be shown again!)"
            else
                print_error "Could not create client secret"
            fi
        fi

        # Add API permissions
        print_step "Configuring API permissions..."
        echo ""
        print_warning "You need to manually add these Microsoft Graph permissions in Azure Portal:"
        echo "  • Mail.Read (Delegated)"
        echo "  • Mail.ReadWrite (Delegated)"
        echo "  • Mail.Send (Delegated)"
        echo "  • User.Read (Delegated)"
        echo "  • User.Read.All (Application) - for admin consent"
        echo ""
        echo "  Portal: https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/CallAnAPI/appId/$APP_ID"

        echo ""
        print_success "Azure setup complete!"
    else
        print_warning "Skipping Azure setup"
    fi
}

setup_virustotal() {
    print_header "Setting Up VirusTotal"

    print_step "Configuring VirusTotal CLI..."
    echo "You need a VirusTotal API key from: https://www.virustotal.com/gui/my-apikey"

    if confirm "Configure VirusTotal now?"; then
        read -p "Enter your VirusTotal API key: " VT_KEY

        if [ -n "$VT_KEY" ]; then
            # Configure vt-cli
            vt init --apikey "$VT_KEY" 2>/dev/null || echo "$VT_KEY" | vt init 2>/dev/null || true

            add_env_var "VIRUSTOTAL_API_KEY" "$VT_KEY"
            print_success "VirusTotal configured!"
        else
            print_warning "No API key provided"
        fi
    else
        print_warning "Skipping VirusTotal setup"
    fi
}

setup_urlscan() {
    print_header "Setting Up URLScan.io"

    print_step "Configuring URLScan CLI..."
    echo "You need a URLScan API key from: https://urlscan.io/user/profile"

    if confirm "Configure URLScan now?"; then
        read -p "Enter your URLScan API key: " URLSCAN_KEY

        if [ -n "$URLSCAN_KEY" ]; then
            # Configure urlscan-cli (if installed)
            if check_command urlscan; then
                echo "$URLSCAN_KEY" | urlscan key set 2>/dev/null || true
            fi

            add_env_var "URLSCAN_API_KEY" "$URLSCAN_KEY"
            print_success "URLScan configured!"
        else
            print_warning "No API key provided"
        fi
    else
        print_warning "Skipping URLScan setup"
    fi
}

setup_manual_services() {
    print_header "Manual Service Setup Required"

    echo "The following services require manual setup via web console:"
    echo ""

    echo -e "${CYAN}1. Clerk (Authentication)${NC}"
    echo "   URL: https://dashboard.clerk.com"
    echo "   Get: CLERK_SECRET_KEY, NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY"
    echo ""

    echo -e "${CYAN}2. Anthropic (Claude LLM)${NC}"
    echo "   URL: https://console.anthropic.com"
    echo "   Get: ANTHROPIC_API_KEY"
    echo ""

    echo -e "${CYAN}3. AbuseIPDB (IP Reputation)${NC}"
    echo "   URL: https://www.abuseipdb.com/account/api"
    echo "   Get: ABUSEIPDB_API_KEY (free: 1000 requests/day)"
    echo ""

    echo -e "${CYAN}4. Google Cloud (Gmail Integration)${NC}"
    echo "   URL: https://console.cloud.google.com/apis/credentials"
    echo "   Get: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET"
    echo "   Enable: Gmail API, Cloud Pub/Sub API"
    echo ""

    echo -e "${CYAN}5. Joe Sandbox (Optional - Paid)${NC}"
    echo "   URL: https://www.joesecurity.org"
    echo "   Get: JOE_SANDBOX_API_KEY"
    echo ""

    echo -e "${CYAN}6. Whoisology (Optional - Domain Age)${NC}"
    echo "   URL: https://whoisology.com/account"
    echo "   Get: WHOISOLOGY_API_KEY"
    echo ""
}

generate_encryption_keys() {
    print_header "Generating Encryption Keys"

    print_step "Generating ENCRYPTION_KEY..."
    ENCRYPTION_KEY=$(openssl rand -base64 32)
    add_env_var "ENCRYPTION_KEY" "$ENCRYPTION_KEY"

    print_step "Generating ENCRYPTION_SALT..."
    ENCRYPTION_SALT=$(openssl rand -base64 16)
    add_env_var "ENCRYPTION_SALT" "$ENCRYPTION_SALT"

    print_success "Encryption keys generated!"
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

show_help() {
    echo "Swordfish Environment Setup Script"
    echo ""
    echo "Usage: ./scripts/setup-env.sh [options]"
    echo ""
    echo "Options:"
    echo "  --all           Run all setup steps"
    echo "  --neon          Setup Neon PostgreSQL only"
    echo "  --upstash       Setup Upstash Redis & Kafka only"
    echo "  --cloudflare    Setup Cloudflare R2 & Workers only"
    echo "  --azure         Setup Azure AD app registration only"
    echo "  --virustotal    Setup VirusTotal CLI only"
    echo "  --urlscan       Setup URLScan.io CLI only"
    echo "  --keys          Generate encryption keys only"
    echo "  --install       Install CLI tools only"
    echo "  --manual        Show manual setup instructions"
    echo "  --help          Show this help message"
    echo ""
    echo "Example:"
    echo "  ./scripts/setup-env.sh --all"
    echo "  ./scripts/setup-env.sh --neon --upstash --keys"
}

main() {
    # Initialize output file
    echo "# Generated environment variables - $(date)" > "$ENV_OUTPUT_FILE"
    echo "# Copy these to your .env.local file" >> "$ENV_OUTPUT_FILE"
    echo "" >> "$ENV_OUTPUT_FILE"

    print_header "SWORDFISH ENVIRONMENT SETUP"
    echo "This script will help you set up the required services for Swordfish."
    echo "Generated environment variables will be saved to: $ENV_OUTPUT_FILE"
    echo ""

    # Parse arguments
    if [ $# -eq 0 ]; then
        show_help
        exit 0
    fi

    RUN_ALL=false
    RUN_NEON=false
    RUN_UPSTASH=false
    RUN_CLOUDFLARE=false
    RUN_AZURE=false
    RUN_VIRUSTOTAL=false
    RUN_URLSCAN=false
    RUN_KEYS=false
    RUN_INSTALL=false
    RUN_MANUAL=false

    for arg in "$@"; do
        case $arg in
            --all) RUN_ALL=true ;;
            --neon) RUN_NEON=true ;;
            --upstash) RUN_UPSTASH=true ;;
            --cloudflare) RUN_CLOUDFLARE=true ;;
            --azure) RUN_AZURE=true ;;
            --virustotal) RUN_VIRUSTOTAL=true ;;
            --urlscan) RUN_URLSCAN=true ;;
            --keys) RUN_KEYS=true ;;
            --install) RUN_INSTALL=true ;;
            --manual) RUN_MANUAL=true ;;
            --help) show_help; exit 0 ;;
            *) echo "Unknown option: $arg"; show_help; exit 1 ;;
        esac
    done

    # Run setup steps
    check_dependencies

    if [ "$RUN_ALL" = true ] || [ "$RUN_INSTALL" = true ]; then
        install_cli_tools
    fi

    if [ "$RUN_ALL" = true ] || [ "$RUN_NEON" = true ]; then
        setup_neon
    fi

    if [ "$RUN_ALL" = true ] || [ "$RUN_UPSTASH" = true ]; then
        setup_upstash
    fi

    if [ "$RUN_ALL" = true ] || [ "$RUN_CLOUDFLARE" = true ]; then
        setup_cloudflare
    fi

    if [ "$RUN_ALL" = true ] || [ "$RUN_AZURE" = true ]; then
        setup_azure
    fi

    if [ "$RUN_ALL" = true ] || [ "$RUN_VIRUSTOTAL" = true ]; then
        setup_virustotal
    fi

    if [ "$RUN_ALL" = true ] || [ "$RUN_URLSCAN" = true ]; then
        setup_urlscan
    fi

    if [ "$RUN_ALL" = true ] || [ "$RUN_KEYS" = true ]; then
        generate_encryption_keys
    fi

    if [ "$RUN_ALL" = true ] || [ "$RUN_MANUAL" = true ]; then
        setup_manual_services
    fi

    # Final summary
    print_header "SETUP COMPLETE"

    echo "Generated environment variables have been saved to: $ENV_OUTPUT_FILE"
    echo ""
    echo "Next steps:"
    echo "  1. Review the generated file: cat $ENV_OUTPUT_FILE"
    echo "  2. Copy variables to .env.local: cat $ENV_OUTPUT_FILE >> .env.local"
    echo "  3. Complete manual service setup (Clerk, Anthropic, Google, AbuseIPDB)"
    echo "  4. Run: npm run dev"
    echo ""

    if [ -f "$ENV_OUTPUT_FILE" ]; then
        echo -e "${GREEN}Generated variables:${NC}"
        cat "$ENV_OUTPUT_FILE" | grep -v "^#" | grep -v "^$"
    fi
}

# Run main function with all arguments
main "$@"
