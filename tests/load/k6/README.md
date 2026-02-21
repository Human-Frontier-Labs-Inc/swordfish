# K6 Load Testing Suite

Production load testing scripts for the Swordfish Email Security Platform.

## Prerequisites

Install k6:
```bash
# macOS
brew install k6

# Windows
choco install k6

# Linux
sudo apt-get install k6
```

## Test Suites

### 1. Health Endpoint (`health.js`)
Basic health check load testing.
```bash
k6 run tests/load/k6/health.js
```

### 2. API Endpoints (`api-endpoints.js`)
Tests multiple API endpoints with realistic traffic patterns.
```bash
k6 run tests/load/k6/api-endpoints.js
```

### 3. Email Analysis (`email-analysis.js`)
Load tests the core email analysis pipeline.
```bash
k6 run tests/load/k6/email-analysis.js
```

### 4. Soak Test (`soak-test.js`)
Extended duration stability test (30 minutes by default).
```bash
k6 run tests/load/k6/soak-test.js
```

## Configuration

### Environment Variables

- `BASE_URL` - Target server URL (default: `http://localhost:3000`)
- `AUTH_TOKEN` - Bearer token for authenticated endpoints

### Running Against Production
```bash
BASE_URL=https://api.swordfish.app AUTH_TOKEN=your_token k6 run tests/load/k6/api-endpoints.js
```

### Custom Duration
```bash
k6 run --duration 10m tests/load/k6/soak-test.js
```

### Custom VUs
```bash
k6 run --vus 50 --duration 5m tests/load/k6/health.js
```

## Thresholds

Each test has predefined thresholds that will cause the test to fail if not met:

| Metric | Health | API | Analysis | Soak |
|--------|--------|-----|----------|------|
| p95 Latency | <500ms | <1000ms | <3000ms | <1500ms |
| p99 Latency | <1000ms | <2000ms | <5000ms | <3000ms |
| Error Rate | <1% | <5% | <5% | <2% |
| Success Rate | >99% | >95% | >95% | >98% |

## Interpreting Results

### Key Metrics
- **http_req_duration** - Request latency
- **http_req_failed** - Failed requests rate
- **vus** - Virtual users
- **iterations** - Completed test iterations

### Output Reports
Generate HTML report:
```bash
k6 run --out json=results.json tests/load/k6/api-endpoints.js
```

## CI/CD Integration

Add to your CI pipeline:
```yaml
- name: Run Load Tests
  run: |
    k6 run --quiet --no-summary tests/load/k6/health.js
    k6 run --quiet --no-summary tests/load/k6/api-endpoints.js
```

## Best Practices

1. **Start Small**: Begin with low VUs and increase gradually
2. **Monitor System**: Watch server metrics during tests
3. **Warm Up**: Allow time for connection pools to initialize
4. **Test in Isolation**: Avoid testing during peak production hours
5. **Baseline First**: Establish baseline performance before optimization
