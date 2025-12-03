## LSC Investigation Tool

Validate Salesforce configuration data against a reference template using either rule-based checks or an optional LLM-powered review. Generates JSON and HTML reports with severity breakdowns and charts.

### Key features
- Rule-based validation of customer config vs. template
- Optional Salesforce extraction (username/password+token, OAuth, or access token)
- Optional LLM validation (Anthropic, OpenAI, or interactive/manual)
- Summary statistics and detailed HTML report

### Project structure
- `rule_based_validator.py`: Main CLI and validation logic
- `templates/template.json`: Sample template configuration
- `customer_data/problematic_customer.json`: Sample customer configuration
- `business_rules.txt`: Example business rules
- `example_llm_response.json`: Sample output format for interactive LLM mode
- `llm_validation_prompt.txt`: Prompt generated when running LLM validations
- `validation_report.json` / `validation_report.html`: Example outputs

## Requirements
- Python 3.10+ recommended

Install dependencies (minimum set):

```bash
python -m venv .venv
source .venv/bin/activate
pip install pandas matplotlib requests
# Optional, for Salesforce extraction:
pip install simple-salesforce
# Optional, for OpenAI provider:
pip install openai
```

Note: Anthropic calls are performed via HTTPS requests and do not require a separate SDK.

## Usage
Run from the project root.

### 1) Validate from files (rule-based)
```bash
python rule_based_validator.py \
  --template templates/template.json \
  --customer customer_data/problematic_customer.json \
  --rules business_rules.txt \
  --output validation_report.json \
  --detailed-report
```

### 2) Validate with Salesforce extraction
Provide one of the supported auth methods:

- Access token:
```bash
python rule_based_validator.py \
  --template templates/template.json \
  --sf-extract \
  --sf-instance-url "https://YOUR_DOMAIN.my.salesforce.com" \
  --sf-access-token "$SF_ACCESS_TOKEN" \
  --rules business_rules.txt \
  --sf-objects LifeSciEmailTemplate LifeSciMarketableProduct \
  --output validation_report.json \
  --detailed-report
```

- Username/password + security token:
```bash
python rule_based_validator.py \
  --template templates/template.json \
  --sf-extract \
  --sf-username "user@example.com" \
  --sf-password "$SF_PASSWORD" \
  --sf-token "$SF_SECURITY_TOKEN" \
  --sf-domain login \
  --rules business_rules.txt \
  --output validation_report.json
```

- OAuth (client credentials or password grant):
```bash
python rule_based_validator.py \
  --template templates/template.json \
  --sf-extract \
  --sf-client-id "$SF_CLIENT_ID" \
  --sf-client-secret "$SF_CLIENT_SECRET" \
  --sf-grant-type client_credentials \
  --sf-instance-url "https://YOUR_DOMAIN.my.salesforce.com" \
  --rules business_rules.txt \
  --output validation_report.json
```

### 3) Validate with LLM
You can switch to AI-powered analysis. Three modes are supported:

- Anthropic (API key or valid `~/.claude/settings.json`):
```bash
python rule_based_validator.py \
  --template templates/template.json \
  --customer customer_data/problematic_customer.json \
  --rules business_rules.txt \
  --use-llm --llm-provider anthropic \
  --anthropic-api-key "$ANTHROPIC_AUTH_TOKEN" \
  --output validation_report_llm.json \
  --detailed-report
```

- OpenAI:
```bash
python rule_based_validator.py \
  --template templates/template.json \
  --customer customer_data/problematic_customer.json \
  --rules business_rules.txt \
  --use-llm --llm-provider openai \
  --openai-api-key "$OPENAI_API_KEY" \
  --llm-model "gpt-4o" \
  --output validation_report_llm.json
```

- Interactive/manual (no API calls; paste prompt to your LLM, then use example output):
```bash
python rule_based_validator.py \
  --template templates/template.json \
  --customer customer_data/problematic_customer.json \
  --rules business_rules.txt \
  --use-llm --llm-provider interactive --interactive \
  --output validation_report_llm.json
```
This will emit a prompt into `llm_validation_prompt.txt` and, by default, read `example_llm_response.json` to demonstrate the expected format.

### Filter by minimum severity
```bash
python rule_based_validator.py ... --filter-severity high
```
Valid values: `low`, `medium`, `high`, `critical`. Shows only that level and above.

## Outputs
- JSON results (summary, issues, counts): `--output <file>.json`
- Detailed HTML report (when `--detailed-report`): `<file>.html` next to the JSON, including:
  - Issue counts by severity (bar chart)
  - Issue tables by severity
  - Completeness by object
  - Metadata and validation method

## Exit codes
- `0`: No issues found
- `1`: Errors or at least one High issue (and no Critical)
- `2`: At least one Critical issue

CLI argument validation or missing dependency errors also return `1` with a descriptive message.

## Tips
- Use `--sf-objects` to limit extraction to specific objects; otherwise objects are inferred from the template.
- For Anthropic, you can supply settings via `~/.claude/settings.json` with `ANTHROPIC_AUTH_TOKEN`.
- The tool disables SSL warnings for convenience; production environments should set strict TLS as appropriate.

## License
Proprietary – internal use only unless stated otherwise.


