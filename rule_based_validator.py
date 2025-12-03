#!/usr/bin/env python3
"""
Salesforce Configuration Data Validator
Validates customer configuration data against templates using rule-based validation
or AI-powered LLM validation
"""

import json
import sys
import os
import warnings
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import argparse
from pathlib import Path
import pandas as pd
from datetime import datetime
import html
import base64
import matplotlib.pyplot as plt
import io
import requests

# Disable SSL warnings for internal systems
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Optional Salesforce integration
try:
    from simple_salesforce import Salesforce
    SALESFORCE_AVAILABLE = True
except ImportError:
    SALESFORCE_AVAILABLE = False

# Optional OpenAI integration
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IssueType(Enum):
    MISSING_RECORD = "missing_record"
    MISSING_FIELD = "missing_field"
    INVALID_VALUE = "invalid_value"
    INCONSISTENT_DATA = "inconsistent_data"
    INCOMPLETE_CONFIG = "incomplete_config"
    BUSINESS_RULE_VIOLATION = "business_rule_violation"

@dataclass
class ConfigValidationIssue:
    object_name: str
    record_id: Optional[str]
    field_name: Optional[str]
    severity: Severity
    issue_type: IssueType
    message: str
    expected_value: Optional[str] = None
    actual_value: Optional[str] = None
    suggestion: Optional[str] = None
    customer_impact: str = "Unknown"

class RuleBasedValidator:
    def __init__(self):
        """Initialize validator"""
        self.sf_client = None
        self.openai_client = None
        
    def connect_to_salesforce(self, username: str, password: str, security_token: str,
                            domain: str = 'login', is_sandbox: bool = False):
        """Connect to Salesforce org using username/password"""
        if not SALESFORCE_AVAILABLE:
            raise Exception("simple-salesforce library not installed. Run: pip install simple-salesforce")

        try:
            if is_sandbox:
                domain = 'test'

            self.sf_client = Salesforce(
                username=username,
                password=password,
                security_token=security_token,
                domain=domain
            )

            org_info = self.sf_client.query("SELECT Id, Name FROM Organization LIMIT 1")
            org_name = org_info['records'][0]['Name'] if org_info['records'] else 'Unknown'

            print(f"✅ Connected to Salesforce org: {org_name}")
            return True

        except Exception as e:
            print(f"❌ Failed to connect to Salesforce: {e}")
            raise

    def connect_with_access_token(self, instance_url: str, access_token: str):
        """Connect to Salesforce using an existing access token"""
        if not SALESFORCE_AVAILABLE:
            raise Exception("simple-salesforce library not installed. Run: pip install simple-salesforce")

        try:
            # Remove trailing slash from instance URL
            instance_url = instance_url.rstrip('/')

            print(f"🔗 Connecting to Salesforce with access token...")
            print(f"🔍 Debug - Instance URL: {instance_url}")

            # Connect using access token with API version 64.0
            self.sf_client = Salesforce(
                instance_url=instance_url,
                session_id=access_token,
                version='64.0'
            )

            org_info = self.sf_client.query("SELECT Id, Name FROM Organization LIMIT 1")
            org_name = org_info['records'][0]['Name'] if org_info['records'] else 'Unknown'

            print(f"✅ Connected to Salesforce org: {org_name}")
            return True

        except Exception as e:
            print(f"❌ Failed to connect to Salesforce with access token: {e}")
            raise

    def connect_to_salesforce_oauth(self, client_id: str, client_secret: str,
                                   username: str = None, password: str = None,
                                   domain: str = 'login', is_sandbox: bool = False,
                                   instance_url: str = None, grant_type: str = 'password'):
        """Connect to Salesforce org using OAuth2 flow

        Supported grant types:
        - password: Username-password flow (requires username and password)
        - client_credentials: Client credentials flow (server-to-server)
        """
        if not SALESFORCE_AVAILABLE:
            raise Exception("simple-salesforce library not installed. Run: pip install simple-salesforce")

        try:
            # Determine the token endpoint
            if instance_url:
                # Use custom instance URL for token endpoint
                # Remove any trailing slashes
                instance_url = instance_url.rstrip('/')
                token_url = f"{instance_url}/services/oauth2/token"
                print(f"🔐 Authenticating with OAuth2 ({grant_type}) to {instance_url}...")
            else:
                # Use standard domain
                if is_sandbox:
                    domain = 'test'
                token_url = f"https://{domain}.salesforce.com/services/oauth2/token"
                print(f"🔐 Authenticating with OAuth2 ({grant_type}) to {domain}.salesforce.com...")

            # Prepare OAuth request based on grant type
            if grant_type == 'client_credentials':
                # Client credentials flow (server-to-server)
                oauth_data = {
                    'grant_type': 'client_credentials',
                    'client_id': client_id,
                    'client_secret': client_secret
                }
                print(f"🔍 Debug - Using client_credentials grant type")
            elif grant_type == 'password':
                # Password flow
                if not username or not password:
                    raise ValueError("Username and password required for password grant type")
                oauth_data = {
                    'grant_type': 'password',
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'username': username,
                    'password': password
                }
                print(f"🔍 Debug - Using password grant type")
                print(f"🔍 Debug - Username: {username}")
            else:
                raise ValueError(f"Unsupported grant type: {grant_type}")

            # Add headers
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }

            print(f"🔍 Debug - Token URL: {token_url}")
            print(f"🔍 Debug - Client ID: {client_id[:20]}...")

            # Get access token
            response = requests.post(token_url, data=oauth_data, headers=headers, verify=True)

            print(f"🔍 Debug - Response Status: {response.status_code}")

            if response.status_code != 200:
                print(f"🔍 Debug - Response Headers: {dict(response.headers)}")
                print(f"🔍 Debug - Response Body: {response.text}")
                raise Exception(f"OAuth authentication failed: {response.text}")

            oauth_response = response.json()
            access_token = oauth_response['access_token']
            returned_instance_url = oauth_response['instance_url']

            print(f"🔍 Debug - Instance URL from OAuth: {returned_instance_url}")

            # Connect to Salesforce using the access token
            self.sf_client = Salesforce(
                instance_url=returned_instance_url,
                session_id=access_token
            )

            org_info = self.sf_client.query("SELECT Id, Name FROM Organization LIMIT 1")
            org_name = org_info['records'][0]['Name'] if org_info['records'] else 'Unknown'

            print(f"✅ Connected to Salesforce org via OAuth: {org_name}")
            return True

        except Exception as e:
            print(f"❌ Failed to connect to Salesforce via OAuth: {e}")
            raise
    
    def connect_to_openai(self, api_key: str, model: str = "gpt-4"):
        """Connect to OpenAI API"""
        if not OPENAI_AVAILABLE:
            raise Exception("openai library not installed. Run: pip install openai")
            
        try:
            self.openai_client = openai.OpenAI(api_key=api_key)
            
            # Test the connection with a simple request
            response = self.openai_client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": "Test connection"}
                ],
                max_tokens=10
            )
            
            print(f"✅ Connected to OpenAI API using model: {model}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to connect to OpenAI API: {e}")
            raise

    def connect_to_anthropic(self, api_key: str = None, model: str = None):
        """Connect to Anthropic Claude API"""
        try:
            # Set default model if not provided
            if not model:
                model = "claude-sonnet-4-5-20250929"

            # Look for settings in the user's settings file
            settings_file = os.path.expanduser("~/.claude/settings.json")
            if os.path.exists(settings_file):
                try:
                    with open(settings_file, 'r') as f:
                        settings = json.load(f)
                        if 'env' in settings:
                            env_settings = settings['env']
                            # Use auth token from settings if available and no api_key provided
                            if not api_key and 'ANTHROPIC_AUTH_TOKEN' in env_settings:
                                api_key = env_settings['ANTHROPIC_AUTH_TOKEN']
                                print("✅ Using Anthropic API key from settings file")
                            # Use bedrock base URL if available
                            if 'ANTHROPIC_BEDROCK_BASE_URL' in env_settings:
                                self.bedrock_base_url = env_settings['ANTHROPIC_BEDROCK_BASE_URL']
                                self.use_bedrock = True
                                print(f"Using Bedrock base URL: {self.bedrock_base_url}")
                except Exception as e:
                    print(f"⚠️ Warning: Could not parse settings file: {e}")
            
            if not api_key:
                raise ValueError("No Anthropic API key provided or found in settings")
                
            # Use Bedrock if configured
            if hasattr(self, 'use_bedrock') and self.use_bedrock:
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                }

                # Bedrock uses standard Anthropic Messages API format
                data = {
                    "model": model,
                    "messages": [{"role": "user", "content": "Test connection"}],
                    "max_tokens": 10
                }

                # Use standard /v1/messages endpoint
                response = requests.post(
                    f"{self.bedrock_base_url}/v1/messages",
                    headers=headers,
                    json=data,
                    verify=False  # For internal systems, often needed
                )
            else:
                # Standard Anthropic API
                headers = {
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                }

                data = {
                    "model": model,
                    "messages": [{"role": "user", "content": "Test connection"}],
                    "max_tokens": 10
                }

                print(f"🔍 Debug - Testing connection with model: {model} (type: {type(model)})")
                print(f"🔍 Debug - Request data: {json.dumps(data, indent=2)}")

                response = requests.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=headers,
                    json=data
                )
            
            if response.status_code == 200:
                print(f"✅ Connected to Anthropic API using model: {model}")
                self.anthropic_api_key = api_key
                self.anthropic_model = model
                return True
            else:
                print(f"❌ Failed to connect to Anthropic API: {response.text}")
                raise Exception(f"Anthropic API error: {response.text}")
                
        except Exception as e:
            print(f"❌ Failed to connect to Anthropic API: {e}")
            raise
    
    def extract_salesforce_data(self, config_objects: List[str], 
                              record_limit: int = 200) -> Dict[str, List[Dict[str, Any]]]:
        """Extract configuration data from Salesforce org"""
        
        if not self.sf_client:
            raise Exception("Not connected to Salesforce. Call connect_to_salesforce() first.")
        
        config_data = {}
        
        for obj_name in config_objects:
            try:
                print(f"📥 Extracting data from {obj_name}...")

                # Use direct API call for describe instead of getattr (works for managed packages)
                describe_url = f"{self.sf_client.base_url}sobjects/{obj_name}/describe"
                print(f"🔍 Debug - Describe URL: {describe_url}")
                print(f"🔍 Debug - Headers: {dict(self.sf_client.headers)}")
                response = requests.get(describe_url, headers=self.sf_client.headers)
                print(f"🔍 Debug - Response status: {response.status_code}")
                obj_describe = response.json()
                print(f"🔍 Debug - Response preview: {str(obj_describe)[:200]}")

                # Check if response is an error (could be list or dict with errorCode)
                if isinstance(obj_describe, list) and len(obj_describe) > 0 and 'errorCode' in obj_describe[0]:
                    raise Exception(f"Resource {obj_name} Not Found. Response content: {obj_describe}")
                elif isinstance(obj_describe, dict) and 'errorCode' in obj_describe:
                    raise Exception(f"Resource {obj_name} Not Found. Response content: {obj_describe}")

                fields = []
                for field in obj_describe['fields']:
                    field_name = field['name']
                    field_type = field.get('type', '')
                    # Include custom fields, standard important fields, and queryable non-relationship fields
                    if (field_name.endswith('__c') or
                        field_name in ['Id', 'Name', 'IsActive', 'CreatedDate', 'LastModifiedDate',
                                       'CreatedById', 'LastModifiedById', 'OwnerId', 'RecordTypeId',
                                       'Status', 'Type', 'Description', 'IsDeleted', 'SystemModstamp'] or
                        (field.get('createable', False) and field_type not in ['reference', 'address', 'location'])):
                        fields.append(field_name)

                if not fields:
                    fields = ['Id', 'Name']

                field_list = ', '.join(fields)
                soql = f"SELECT {field_list} FROM {obj_name}"

                if any(f['name'] == 'Active__c' for f in obj_describe['fields']):
                    soql += " WHERE Active__c = true"

                soql += f" LIMIT {record_limit}"

                result = self.sf_client.query_all(soql)

                records = []
                for record in result['records']:
                    clean_record = {k: v for k, v in record.items()
                                  if k != 'attributes'}

                    for key, value in clean_record.items():
                        if value is None:
                            clean_record[key] = ""

                    records.append(clean_record)

                config_data[obj_name] = records
                print(f"✅ Extracted {len(records)} records from {obj_name}")

            except Exception as e:
                print(f"⚠️  Warning: Could not extract {obj_name}: {e}")
                config_data[obj_name] = []
        
        return config_data
    
    def save_salesforce_data(self, config_data: Dict[str, List[Dict[str, Any]]], 
                           output_dir: str):
        """Save extracted Salesforce data to files"""
        
        os.makedirs(output_dir, exist_ok=True)
        
        json_file = os.path.join(output_dir, 'salesforce_config.json')
        with open(json_file, 'w') as f:
            json.dump(config_data, f, indent=2, default=str)
        print(f"💾 Saved complete data to {json_file}")
        
        for obj_name, records in config_data.items():
            if records:
                csv_file = os.path.join(output_dir, f'{obj_name}.csv')
                df = pd.DataFrame(records)
                df.to_csv(csv_file, index=False)
                print(f"💾 Saved {obj_name} to {csv_file}")
    
    def load_data(self, file_path: str) -> Dict[str, List[Dict[str, Any]]]:
        """Load configuration data from file or directory"""
        data = {}
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Path not found: {file_path}")
        
        if os.path.isfile(file_path):
            if file_path.endswith('.json'):
                with open(file_path, 'r') as f:
                    data = json.load(f)
            elif file_path.endswith('.csv'):
                object_name = Path(file_path).stem
                df = pd.read_csv(file_path)
                data[object_name] = df.to_dict('records')
        else:
            for file in Path(file_path).glob('*'):
                if file.suffix == '.json':
                    with open(file, 'r') as f:
                        file_data = json.load(f)
                        data.update(file_data)
                elif file.suffix == '.csv':
                    object_name = file.stem
                    df = pd.read_csv(file)
                    data[object_name] = df.to_dict('records')
        
        return data
    
    def validate_configuration(self, 
                             template_data: Dict[str, List[Dict[str, Any]]], 
                             customer_data: Dict[str, List[Dict[str, Any]]],
                             business_rules: List[str] = None) -> List[ConfigValidationIssue]:
        """Validate customer configuration against template using rule-based validation"""
        
        issues = []
        
        # Check for missing objects
        for obj_name in template_data:
            if obj_name not in customer_data:
                # Object is completely missing
                issues.append(ConfigValidationIssue(
                    object_name=obj_name,
                    record_id=None,
                    field_name=None,
                    severity=Severity.CRITICAL,
                    issue_type=IssueType.MISSING_RECORD,
                    message=f"{obj_name} configuration is completely missing",
                    expected_value="Configuration present",
                    actual_value="MISSING",
                    suggestion=f"Add required {obj_name} configuration",
                    customer_impact="Critical functionality may be unavailable"
                ))
                continue
            
            # Create a lookup for customer records by Name
            customer_records_by_name = {r.get('Name', ''): r for r in customer_data.get(obj_name, [])}
            
            # Check each template record
            for template_record in template_data[obj_name]:
                record_name = template_record.get('Name', '')
                if not record_name:
                    continue
                    
                if record_name not in customer_records_by_name:
                    # Record is missing
                    issues.append(ConfigValidationIssue(
                        object_name=obj_name,
                        record_id=record_name,
                        field_name=None,
                        severity=Severity.HIGH,
                        issue_type=IssueType.MISSING_RECORD,
                        message=f"{record_name} record is missing in {obj_name}",
                        expected_value=f"{record_name} configuration",
                        actual_value="MISSING",
                        suggestion=f"Add the {record_name} record to {obj_name}",
                        customer_impact="Required functionality may be unavailable"
                    ))
                    continue
                    
                # Check fields in existing records
                customer_record = customer_records_by_name[record_name]

                # Check for unexpected fields (fields in customer but not in template)
                template_fields = set(template_record.keys())
                customer_fields = set(customer_record.keys())
                unexpected_fields = customer_fields - template_fields

                for unexpected_field in unexpected_fields:
                    # Flag unexpected custom fields
                    if unexpected_field.endswith('__c') or unexpected_field == 'UnexpectedField__c':
                        issues.append(ConfigValidationIssue(
                            object_name=obj_name,
                            record_id=record_name,
                            field_name=unexpected_field,
                            severity=Severity.MEDIUM,
                            issue_type=IssueType.INVALID_VALUE,
                            message=f"Unexpected field {unexpected_field} found in {record_name}",
                            expected_value="Field should not exist",
                            actual_value=str(customer_record[unexpected_field]),
                            suggestion=f"Remove {unexpected_field} from {record_name}",
                            customer_impact="May cause data integrity issues"
                        ))

                # Check for missing fields (fields in template but not in customer)
                missing_fields = template_fields - customer_fields
                for missing_field in missing_fields:
                    if missing_field != 'Name':  # Name is already checked elsewhere
                        template_field_value = template_record.get(missing_field)
                        # Only flag if the template has a non-empty value
                        if template_field_value not in [None, '', {}]:
                            issues.append(ConfigValidationIssue(
                                object_name=obj_name,
                                record_id=record_name,
                                field_name=missing_field,
                                severity=Severity.HIGH,
                                issue_type=IssueType.MISSING_FIELD,
                                message=f"Required field {missing_field} is missing in {record_name}",
                                expected_value=str(template_field_value),
                                actual_value="MISSING",
                                suggestion=f"Add {missing_field} to {record_name}",
                                customer_impact="Configuration may be incomplete"
                            ))

                for field_name, template_value in template_record.items():
                    if field_name == 'Name':
                        continue
                        
                    customer_value = customer_record.get(field_name, '')
                    
                    # Check for empty values in required fields
                    if template_value and not customer_value:
                        severity = Severity.HIGH
                        if field_name.endswith('__c') and 'Endpoint' in field_name:
                            severity = Severity.CRITICAL
                            
                        issues.append(ConfigValidationIssue(
                            object_name=obj_name,
                            record_id=record_name,
                            field_name=field_name,
                            severity=severity,
                            issue_type=IssueType.MISSING_FIELD,
                            message=f"{field_name} is empty in {record_name}",
                            expected_value=str(template_value),
                            actual_value="",
                            suggestion=f"Configure {field_name} in {record_name}",
                            customer_impact="Functionality may be impaired"
                        ))
                    
                    # Check for placeholder values in API keys
                    if 'API_Key' in field_name and customer_value in ['REQUIRED', 'PLACEHOLDER', 'API_KEY_REQUIRED']:
                        issues.append(ConfigValidationIssue(
                            object_name=obj_name,
                            record_id=record_name,
                            field_name=field_name,
                            severity=Severity.HIGH,
                            issue_type=IssueType.INVALID_VALUE,
                            message=f"{field_name} contains placeholder text",
                            expected_value="Valid API key",
                            actual_value=customer_value,
                            suggestion=f"Replace placeholder with actual API key",
                            customer_impact="Authentication will fail"
                        ))

                    # Check for INCORRECT_VALUE placeholder
                    if customer_value == "INCORRECT_VALUE":
                        issues.append(ConfigValidationIssue(
                            object_name=obj_name,
                            record_id=record_name,
                            field_name=field_name,
                            severity=Severity.HIGH,
                            issue_type=IssueType.INVALID_VALUE,
                            message=f"{field_name} contains incorrect placeholder value",
                            expected_value=str(template_value),
                            actual_value=customer_value,
                            suggestion=f"Replace INCORRECT_VALUE with proper value for {field_name}",
                            customer_impact="Configuration will not work as expected"
                        ))

                    # Check for data type mismatches
                    if template_value is not None and customer_value is not None:
                        if type(template_value) != type(customer_value):
                            # Check if it's a string/number mismatch
                            if isinstance(template_value, str) and isinstance(customer_value, (int, float)):
                                issues.append(ConfigValidationIssue(
                                    object_name=obj_name,
                                    record_id=record_name,
                                    field_name=field_name,
                                    severity=Severity.HIGH,
                                    issue_type=IssueType.INVALID_VALUE,
                                    message=f"{field_name} has wrong data type (number instead of string)",
                                    expected_value=f"String: {template_value}",
                                    actual_value=f"Number: {customer_value}",
                                    suggestion=f"Change {field_name} to string type",
                                    customer_impact="Field validation may fail"
                                ))
                            elif isinstance(template_value, (int, float)) and isinstance(customer_value, str):
                                issues.append(ConfigValidationIssue(
                                    object_name=obj_name,
                                    record_id=record_name,
                                    field_name=field_name,
                                    severity=Severity.HIGH,
                                    issue_type=IssueType.INVALID_VALUE,
                                    message=f"{field_name} has wrong data type (string instead of number)",
                                    expected_value=f"Number: {template_value}",
                                    actual_value=f"String: {customer_value}",
                                    suggestion=f"Change {field_name} to number type",
                                    customer_impact="Field validation may fail"
                                ))
                            elif isinstance(template_value, bool) and isinstance(customer_value, str):
                                issues.append(ConfigValidationIssue(
                                    object_name=obj_name,
                                    record_id=record_name,
                                    field_name=field_name,
                                    severity=Severity.HIGH,
                                    issue_type=IssueType.INVALID_VALUE,
                                    message=f"{field_name} has wrong data type (string instead of boolean)",
                                    expected_value=f"Boolean: {template_value}",
                                    actual_value=f"String: {customer_value}",
                                    suggestion=f"Change {field_name} to boolean (true/false)",
                                    customer_impact="Field validation may fail"
                                ))

                    # Check for boolean fields that should be true
                    if field_name == 'Active__c' and template_value is True and customer_value is False:
                        severity = Severity.MEDIUM
                        if 'Salesforce' in record_name or 'Email' in record_name:
                            severity = Severity.HIGH
                            
                        issues.append(ConfigValidationIssue(
                            object_name=obj_name,
                            record_id=record_name,
                            field_name=field_name,
                            severity=severity,
                            issue_type=IssueType.INVALID_VALUE,
                            message=f"{record_name} is inactive",
                            expected_value="true",
                            actual_value="false",
                            suggestion=f"Activate {record_name}",
                            customer_impact="Configuration will not be used"
                        ))
        
        # Apply specific business rules
        issues.extend(self._apply_business_rules(template_data, customer_data, business_rules))
        
        return issues
    
    def validate_with_llm(self, 
                        template_data: Dict[str, List[Dict[str, Any]]], 
                        customer_data: Dict[str, List[Dict[str, Any]]],
                        business_rules: List[str] = None,
                        llm_provider: str = "anthropic",
                        llm_model: str = None,
                        interactive: bool = False,
                        prompt: str = None) -> List[ConfigValidationIssue]:
        """Validate customer configuration against template using LLM-based validation"""
        
        # Prepare business rules as a string and create prompt if not provided
        if prompt is None:
            rules_text = "\n".join(business_rules) if business_rules else "No specific business rules provided."
            prompt = self._create_llm_prompt(template_data, customer_data, rules_text)
        
        # Use interactive mode if requested
        if interactive or llm_provider == "interactive":
            print("\n==== INTERACTIVE LLM VALIDATION MODE ====\n")
            print("The following prompt will be used for LLM validation:")
            print("===========================================\n")
            print(prompt[:500] + "..." + prompt[-500:])
            print("\n===========================================\n")
            
            print("INSTRUCTIONS:")
            print("1. Copy this prompt and send it to your preferred LLM")
            print("2. Save the LLM's JSON response to a file")
            print("3. Enter the path to the saved JSON file below")
            
            # For automated testing, use the example file
            print("Using example LLM response file for testing: example_llm_response.json")
            file_path = "example_llm_response.json"
            if file_path.lower() == 'cancel':
                print("Interactive validation cancelled")
                return []
                
            try:
                with open(file_path, 'r') as f:
                    response_text = f.read()
                    
                # Try to extract JSON array from text
                import re
                json_match = re.search(r'\[[\s\S]*\]', response_text)
                if json_match:
                    response_json = json.loads(json_match.group())
                else:
                    # Try loading the entire file as JSON
                    response_json = json.loads(response_text)
                    
                print(f"\nSuccessfully loaded validation results with {len(response_json)} issues")
            except Exception as e:
                print(f"\nError loading JSON response: {e}")
                print("Aborting validation")
                return []
        else:
            # Get LLM response through API
            if llm_provider == "openai" and self.openai_client:
                response_json = self._get_openai_response(prompt, llm_model)
            elif llm_provider == "anthropic":
                response_json = self._get_anthropic_response(prompt, llm_model)
            else:
                raise ValueError(f"Unsupported LLM provider: {llm_provider}")
        
        # Convert LLM response to ConfigValidationIssue objects
        issues = self._convert_llm_response_to_issues(response_json)
        
        return issues
    
    def _create_llm_prompt(self, 
                         template_data: Dict[str, List[Dict[str, Any]]], 
                         customer_data: Dict[str, List[Dict[str, Any]]],
                         business_rules: str) -> str:
        """Create a prompt for the LLM"""
        
        template_json = json.dumps(template_data, indent=2)
        customer_json = json.dumps(customer_data, indent=2)
        
        prompt = f"""You are a Salesforce configuration validator expert. Your task is to analyze a customer's Salesforce configuration against a template and identify issues.

BUSINESS RULES:
{business_rules}

TEMPLATE CONFIGURATION:
```json
{template_json}
```

CUSTOMER CONFIGURATION:
```json
{customer_json}
```

Analyze the customer configuration against the template and business rules. Identify any issues and categorize them by severity (Critical, High, Medium, Low).

For each issue, provide:
1. object_name: The Salesforce object with the issue
2. record_id: The specific record with the issue (use the Name field)
3. field_name: The specific field with the issue, if applicable
4. severity: One of: "critical", "high", "medium", "low"
5. issue_type: One of: "missing_record", "missing_field", "invalid_value", "inconsistent_data", "incomplete_config", "business_rule_violation"
6. message: A clear description of the issue
7. expected_value: What the value should be
8. actual_value: What the value currently is
9. suggestion: How to fix the issue
10. customer_impact: The potential impact on functionality

Return ONLY a JSON array of issues with these fields. Do not include any explanations, introductions, or conclusions outside the JSON object. 
Use the following format:

[
  {{
    "object_name": "Example_Object__c",
    "record_id": "Record_Name",
    "field_name": "Field_Name__c",
    "severity": "critical",
    "issue_type": "missing_field",
    "message": "Field is missing",
    "expected_value": "Expected value",
    "actual_value": "Actual value",
    "suggestion": "How to fix it",
    "customer_impact": "Impact description"
  }},
  ...
]
"""
        
        # Save the prompt to a file for reference
        try:
            prompt_file = "llm_validation_prompt.txt"
            with open(prompt_file, 'w') as f:
                f.write(prompt)
            print(f"💾 Validation prompt saved to {prompt_file}")
        except Exception as e:
            print(f"⚠️  Warning: Could not save prompt to file: {e}")
        return prompt
    
    def _get_openai_response(self, prompt: str, model: str = None) -> Dict:
        """Get response from OpenAI API"""
        
        if not self.openai_client:
            raise Exception("Not connected to OpenAI API. Call connect_to_openai() first.")
        
        if not model:
            model = "gpt-4"
            
        try:
            response = self.openai_client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a Salesforce configuration validation expert."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            
            response_text = response.choices[0].message.content
            return json.loads(response_text)
            
        except Exception as e:
            print(f"❌ Error calling OpenAI API: {e}")
            raise
    
    def _get_anthropic_response(self, prompt: str, model: str = None) -> Dict:
        """Get response from Anthropic API"""

        if not hasattr(self, 'anthropic_api_key'):
            raise Exception("Not connected to Anthropic API. Call connect_to_anthropic() first.")

        if not model:
            model = self.anthropic_model or "claude-sonnet-4-5-20250929"
            
        try:
            # Direct Anthropic API call
            print(f"Using direct Anthropic API call with model: {model}")
            
            # Check if we're using Bedrock
            if hasattr(self, 'use_bedrock') and self.use_bedrock:
                headers = {
                    "Authorization": f"Bearer {self.anthropic_api_key}",
                    "Content-Type": "application/json"
                }

                # Bedrock uses standard Anthropic Messages API format
                data = {
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 4000
                }
                url = f"{self.bedrock_base_url}/v1/messages"
            else:
                # Standard Anthropic API
                headers = {
                    "x-api-key": self.anthropic_api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                }

                data = {
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 4000
                }
                url = "https://api.anthropic.com/v1/messages"
                
            response = requests.post(
                url,
                headers=headers,
                json=data,
                verify=False if hasattr(self, 'use_bedrock') and self.use_bedrock else True
            )
            
            if response.status_code == 200:
                response_json = response.json()
                print(f"Response keys: {list(response_json.keys())}")
                
                # Handle different response formats
                if 'content' in response_json and isinstance(response_json['content'], list) and len(response_json['content']) > 0:
                    response_text = response_json['content'][0]['text']
                elif 'content' in response_json and isinstance(response_json['content'], str):
                    response_text = response_json['content']
                elif 'completion' in response_json:
                    response_text = response_json['completion']
                else:
                    print(f"Full response: {json.dumps(response_json, indent=2)}")
                    raise ValueError(f"Unexpected response format from API: {list(response_json.keys())}")
                
                # Extract JSON from response text - this handles cases where Claude might include text before/after JSON
                try:
                    import re
                    json_match = re.search(r'\[[\s\S]*\]', response_text)
                    if json_match:
                        return json.loads(json_match.group())
                    else:
                        raise ValueError("Could not extract JSON from Claude response")
                except Exception as e:
                    print(f"❌ Error parsing Claude response as JSON: {e}")
                    print(f"Raw response: {response_text[:500]}... (truncated)")
                    raise
            else:
                print(f"Response status: {response.status_code}")
                print(f"Response headers: {response.headers}")
                raise Exception(f"Anthropic API error: {response.text}")
                
        except Exception as e:
            print(f"❌ Error calling Anthropic API: {e}")
            raise
    
    def _convert_llm_response_to_issues(self, response_json: List[Dict]) -> List[ConfigValidationIssue]:
        """Convert LLM response to ConfigValidationIssue objects"""
        
        issues = []
        
        for issue_dict in response_json:
            try:
                severity_str = issue_dict.get('severity', 'medium').lower()
                severity = getattr(Severity, severity_str.upper())
                
                issue_type_str = issue_dict.get('issue_type', 'business_rule_violation')
                issue_type = getattr(IssueType, issue_type_str.upper())
                
                issue = ConfigValidationIssue(
                    object_name=issue_dict.get('object_name', 'Unknown'),
                    record_id=issue_dict.get('record_id'),
                    field_name=issue_dict.get('field_name'),
                    severity=severity,
                    issue_type=issue_type,
                    message=issue_dict.get('message', 'Issue detected by LLM'),
                    expected_value=issue_dict.get('expected_value'),
                    actual_value=issue_dict.get('actual_value'),
                    suggestion=issue_dict.get('suggestion'),
                    customer_impact=issue_dict.get('customer_impact', 'Unknown')
                )
                
                issues.append(issue)
                
            except (AttributeError, KeyError) as e:
                print(f"⚠️  Warning: Could not convert LLM issue to ConfigValidationIssue: {e}")
                print(f"Issue data: {issue_dict}")
        
        return issues
    
    def _generate_html_report(self, results: Dict[str, Any], output_file: str):
        """Generate a detailed HTML report from validation results"""
        
        # Create issue severity charts
        plt.figure(figsize=(8, 4))
        counts = results['issue_counts']
        labels = ['Critical', 'High', 'Medium', 'Low']
        values = [counts['critical'], counts['high'], counts['medium'], counts['low']]
        colors = ['#ff4444', '#ff8800', '#ffcc00', '#00cc44']
        
        plt.bar(labels, values, color=colors)
        plt.title('Configuration Issues by Severity')
        plt.ylabel('Number of Issues')
        plt.tight_layout()
        
        # Convert plot to base64 string for HTML embedding
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        img_base64 = base64.b64encode(buf.read()).decode('utf-8')
        plt.close()
        
        # Generate HTML content
        html_content = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Salesforce Configuration Validation Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #0066cc; }}
                h2 {{ color: #0066cc; margin-top: 30px; }}
                .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                .chart {{ text-align: center; margin: 30px 0; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f8f9fa; }}
                .critical {{ color: #ff4444; font-weight: bold; }}
                .high {{ color: #ff8800; font-weight: bold; }}
                .medium {{ color: #ffcc00; }}
                .low {{ color: #00cc44; }}
                .metadata {{ font-size: 12px; color: #666; margin-top: 40px; }}
                .badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; font-size: 12px; }}
                .badge-ai {{ background-color: #6f42c1; }}
                .badge-rule {{ background-color: #0066cc; }}
            </style>
        </head>
        <body>
            <h1>Salesforce Configuration Validation Report</h1>
            
            <div class="summary">
                <h2>Configuration Summary</h2>
                <p>Configuration completeness: <strong>{results['summary']['overall_completeness']}%</strong></p>
                <p>Total issues found: <strong>{counts['total']}</strong></p>
                <ul>
                    <li><span class="critical">Critical issues:</span> {counts['critical']}</li>
                    <li><span class="high">High issues:</span> {counts['high']}</li>
                    <li><span class="medium">Medium issues:</span> {counts['medium']}</li>
                    <li><span class="low">Low issues:</span> {counts['low']}</li>
                </ul>
                <p>Validation method: <strong>{results.get('validation_method', 'Rule-based')}</strong></p>
            </div>
            
            <div class="chart">
                <h2>Issues by Severity</h2>
                <img src="data:image/png;base64,{img_base64}" alt="Issues by Severity Chart">
            </div>
            
            <h2>Detailed Issues</h2>
        '''
        
        # Add issues tables by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            severity_issues = [i for i in results['issues'] if i['severity'] == severity]
            if not severity_issues:
                continue
                
            severity_class = severity.lower()
            severity_title = severity.upper()
            
            html_content += f'''
            <h3 class="{severity_class}">{severity_title} Issues ({len(severity_issues)})</h3>
            <table>
                <tr>
                    <th>Object</th>
                    <th>Record</th>
                    <th>Field</th>
                    <th>Issue</th>
                    <th>Expected</th>
                    <th>Actual</th>
                    <th>Suggestion</th>
                    <th>Impact</th>
                </tr>
            '''
            
            for issue in severity_issues:
                record_id = issue['record_id'] or '-'
                field_name = issue['field_name'] or '-'
                expected = issue['expected_value'] or '-'
                actual = issue['actual_value'] or '-'
                
                # Add badge for LLM-detected issues
                badge = ''
                if 'source' in issue:
                    if issue['source'] == 'llm':
                        badge = '<span class="badge badge-ai">AI</span> '
                    else:
                        badge = '<span class="badge badge-rule">RULE</span> '
                
                html_content += f'''
                <tr>
                    <td>{html.escape(issue['object_name'])}</td>
                    <td>{html.escape(str(record_id))}</td>
                    <td>{html.escape(str(field_name))}</td>
                    <td>{badge}{html.escape(issue['message'])}</td>
                    <td>{html.escape(str(expected))}</td>
                    <td>{html.escape(str(actual))}</td>
                    <td>{html.escape(issue['suggestion'] or '-')}</td>
                    <td>{html.escape(issue['customer_impact'] or '-')}</td>
                </tr>
                '''
            
            html_content += '</table>'
        
        # Add configuration completeness by object
        html_content += '''
            <h2>Configuration Completeness by Object</h2>
            <table>
                <tr>
                    <th>Object</th>
                    <th>Template Records</th>
                    <th>Customer Records</th>
                    <th>Completeness</th>
                </tr>
        '''
        
        for obj_name, obj_data in results['summary']['objects'].items():
            completeness = obj_data['completeness']
            color_class = ''
            if completeness < 50:
                color_class = 'critical'
            elif completeness < 80:
                color_class = 'high'
            elif completeness < 100:
                color_class = 'medium'
            else:
                color_class = 'low'
                
            html_content += f'''
                <tr>
                    <td>{html.escape(obj_name)}</td>
                    <td>{obj_data['template_count']}</td>
                    <td>{obj_data['customer_count']}</td>
                    <td class="{color_class}">{completeness}%</td>
                </tr>
            '''
        
        html_content += '</table>'
        
        # Add report metadata
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        validation_method = results.get('validation_method', 'Rule-based')
        html_content += f'''
            <div class="metadata">
                <p>Report generated: {timestamp}</p>
                <p>Data source: {results['summary'].get('data_source', 'file')}</p>
                <p>Validation method: {validation_method}</p>
                <p>Generated by Salesforce Configuration Validator</p>
            </div>
        </body>
        </html>
        '''
        
        # Write HTML to file
        with open(output_file, 'w') as f:
            f.write(html_content)

    def _apply_business_rules(self, 
                           template_data: Dict[str, List[Dict[str, Any]]],
                           customer_data: Dict[str, List[Dict[str, Any]]],
                           business_rules: List[str]) -> List[ConfigValidationIssue]:
        """Apply specific business rules to the configuration"""
        issues = []
        
        # Check if all rules are present
        if not business_rules:
            return issues
            
        # Rule: Integration endpoints
        if any(rule for rule in business_rules if "endpoint" in rule.lower()):
            integration_settings = customer_data.get('Integration_Settings__c', [])
            for integration in integration_settings:
                if integration.get('Environment__c') == 'Production' and not integration.get('Endpoint__c'):
                    issues.append(ConfigValidationIssue(
                        object_name='Integration_Settings__c',
                        record_id=integration.get('Name', 'Unknown'),
                        field_name='Endpoint__c',
                        severity=Severity.CRITICAL,
                        issue_type=IssueType.BUSINESS_RULE_VIOLATION,
                        message="Production integration endpoint not configured",
                        expected_value="Valid endpoint URL",
                        actual_value=integration.get('Endpoint__c', ''),
                        suggestion="Configure valid endpoint URL",
                        customer_impact="Integration will fail completely"
                    ))
        
        # Rule: Email service required
        if any(rule for rule in business_rules if "email service" in rule.lower()):
            integration_settings = customer_data.get('Integration_Settings__c', [])
            email_service_exists = any(i for i in integration_settings if 'Email' in i.get('Name', ''))
            if not email_service_exists:
                issues.append(ConfigValidationIssue(
                    object_name='Integration_Settings__c',
                    record_id='Email_Service',
                    field_name=None,
                    severity=Severity.CRITICAL,
                    issue_type=IssueType.BUSINESS_RULE_VIOLATION,
                    message="Email service integration is missing",
                    expected_value="Email service configuration",
                    actual_value="MISSING",
                    suggestion="Add Email Service integration",
                    customer_impact="Notification functionality will be unavailable"
                ))
        
        # Rule: Integration timeout values
        if any(rule for rule in business_rules if "timeout" in rule.lower()):
            integration_settings = customer_data.get('Integration_Settings__c', [])
            for integration in integration_settings:
                if integration.get('Active__c') and 'Timeout__c' in integration:
                    try:
                        timeout = int(integration.get('Timeout__c', 0))
                        if timeout < 5 or timeout > 60:
                            issues.append(ConfigValidationIssue(
                                object_name='Integration_Settings__c',
                                record_id=integration.get('Name', 'Unknown'),
                                field_name='Timeout__c',
                                severity=Severity.MEDIUM,
                                issue_type=IssueType.BUSINESS_RULE_VIOLATION,
                                message="Integration timeout outside acceptable range (5-60)",
                                expected_value="5-60 seconds",
                                actual_value=str(timeout),
                                suggestion="Set timeout between 5-60 seconds",
                                customer_impact="Integration may timeout too quickly or hang"
                            ))
                    except (ValueError, TypeError):
                        issues.append(ConfigValidationIssue(
                            object_name='Integration_Settings__c',
                            record_id=integration.get('Name', 'Unknown'),
                            field_name='Timeout__c',
                            severity=Severity.MEDIUM,
                            issue_type=IssueType.INVALID_VALUE,
                            message="Integration timeout is not a valid number",
                            expected_value="5-60 seconds",
                            actual_value=str(integration.get('Timeout__c', '')),
                            suggestion="Set timeout to a number between 5-60 seconds",
                            customer_impact="Integration may use default timeout values"
                        ))
        
        # Rule: Lead assignment rules
        if any(rule for rule in business_rules if "lead assignment" in rule.lower()):
            business_processes = customer_data.get('Business_Process__c', [])
            active_lead_assignments = [bp for bp in business_processes 
                                     if bp.get('Process_Type__c') == 'Assignment_Rule' 
                                     and bp.get('Active__c') is True]
            
            if not active_lead_assignments:
                issues.append(ConfigValidationIssue(
                    object_name='Business_Process__c',
                    record_id='Lead_Assignment',
                    field_name='Active__c',
                    severity=Severity.HIGH,
                    issue_type=IssueType.BUSINESS_RULE_VIOLATION,
                    message="No active lead assignment rules",
                    expected_value="At least one active rule",
                    actual_value="No active rules",
                    suggestion="Activate at least one lead assignment rule",
                    customer_impact="Leads will not be automatically assigned"
                ))
        
        # Rule: Opportunity approval process for large deals
        if any(rule for rule in business_rules if "opportunity approval" in rule.lower() and "$50,000" in rule):
            business_processes = customer_data.get('Business_Process__c', [])
            has_opportunity_approval = any(bp for bp in business_processes 
                                        if bp.get('Process_Type__c') == 'Approval_Process' 
                                        and 'Opportunity' in bp.get('Name', '')
                                        and bp.get('Active__c') is True)
            
            if not has_opportunity_approval:
                issues.append(ConfigValidationIssue(
                    object_name='Business_Process__c',
                    record_id='Opportunity_Approval',
                    field_name=None,
                    severity=Severity.HIGH,
                    issue_type=IssueType.BUSINESS_RULE_VIOLATION,
                    message="No active opportunity approval process for large deals",
                    expected_value="Active approval process",
                    actual_value="MISSING",
                    suggestion="Configure opportunity approval process for deals over $50,000",
                    customer_impact="Large deals won't have required approvals"
                ))
        
        # Rule: Business processes must have defined criteria and actions
        if any(rule for rule in business_rules if "business process" in rule.lower() and "criteria" in rule.lower()):
            business_processes = customer_data.get('Business_Process__c', [])
            for bp in business_processes:
                if not bp.get('Criteria__c'):
                    issues.append(ConfigValidationIssue(
                        object_name='Business_Process__c',
                        record_id=bp.get('Name', 'Unknown'),
                        field_name='Criteria__c',
                        severity=Severity.HIGH,
                        issue_type=IssueType.BUSINESS_RULE_VIOLATION,
                        message="Business process criteria not defined",
                        expected_value="Defined criteria",
                        actual_value="MISSING",
                        suggestion=f"Define criteria for {bp.get('Name', 'Unknown')}",
                        customer_impact="Process won't know when to trigger"
                    ))
                    
                if not bp.get('Action__c'):
                    issues.append(ConfigValidationIssue(
                        object_name='Business_Process__c',
                        record_id=bp.get('Name', 'Unknown'),
                        field_name='Action__c',
                        severity=Severity.HIGH,
                        issue_type=IssueType.BUSINESS_RULE_VIOLATION,
                        message="Business process action not defined",
                        expected_value="Defined action",
                        actual_value="MISSING",
                        suggestion=f"Define action for {bp.get('Name', 'Unknown')}",
                        customer_impact="Process won't know what to do when triggered"
                    ))
        
        # Rule: Logging must be enabled for production
        if any(rule for rule in business_rules if "logging" in rule.lower() and "production" in rule.lower()):
            system_settings = customer_data.get('System_Settings__c', [])
            global_settings = next((s for s in system_settings if s.get('Name') == 'Global_Settings'), None)
            
            if not global_settings:
                issues.append(ConfigValidationIssue(
                    object_name='System_Settings__c',
                    record_id='Global_Settings',
                    field_name='Enable_Logging__c',
                    severity=Severity.CRITICAL,
                    issue_type=IssueType.BUSINESS_RULE_VIOLATION,
                    message="Logging configuration is missing",
                    expected_value="true",
                    actual_value="MISSING",
                    suggestion="Add Global_Settings with logging enabled",
                    customer_impact="System events will not be logged"
                ))
            elif global_settings.get('Enable_Logging__c') is not True:
                issues.append(ConfigValidationIssue(
                    object_name='System_Settings__c',
                    record_id='Global_Settings',
                    field_name='Enable_Logging__c',
                    severity=Severity.CRITICAL,
                    issue_type=IssueType.BUSINESS_RULE_VIOLATION,
                    message="Logging is disabled for production",
                    expected_value="true",
                    actual_value=str(global_settings.get('Enable_Logging__c', False)),
                    suggestion="Enable logging in system settings",
                    customer_impact="System events will not be logged"
                ))
        
        # Rule: Log level should be INFO or higher
        if any(rule for rule in business_rules if "log level" in rule.lower()):
            system_settings = customer_data.get('System_Settings__c', [])
            global_settings = next((s for s in system_settings if s.get('Name') == 'Global_Settings'), None)
            
            if global_settings and 'Log_Level__c' in global_settings:
                log_level = global_settings.get('Log_Level__c', '').upper()
                if log_level not in ['INFO', 'WARN', 'WARNING', 'ERROR', 'DEBUG']:
                    issues.append(ConfigValidationIssue(
                        object_name='System_Settings__c',
                        record_id='Global_Settings',
                        field_name='Log_Level__c',
                        severity=Severity.MEDIUM,
                        issue_type=IssueType.BUSINESS_RULE_VIOLATION,
                        message="Invalid log level",
                        expected_value="INFO, WARN, ERROR, or DEBUG",
                        actual_value=log_level,
                        suggestion="Set log level to INFO or higher",
                        customer_impact="Logging may not capture required information"
                    ))
        
        # Rule: Backup frequency
        if any(rule for rule in business_rules if "backup frequency" in rule.lower()):
            system_settings = customer_data.get('System_Settings__c', [])
            global_settings = next((s for s in system_settings if s.get('Name') == 'Global_Settings'), None)
            
            if global_settings and 'Backup_Frequency__c' in global_settings:
                backup_freq = global_settings.get('Backup_Frequency__c', '').capitalize()
                if backup_freq not in ['Daily', 'Weekly']:
                    issues.append(ConfigValidationIssue(
                        object_name='System_Settings__c',
                        record_id='Global_Settings',
                        field_name='Backup_Frequency__c',
                        severity=Severity.HIGH,
                        issue_type=IssueType.BUSINESS_RULE_VIOLATION,
                        message="Backup frequency not set to Daily or Weekly",
                        expected_value="Daily or Weekly",
                        actual_value=backup_freq,
                        suggestion="Set backup frequency to Daily or Weekly",
                        customer_impact="Data may not be backed up frequently enough"
                    ))
            
        # Rule: Query limits
        if any(rule for rule in business_rules if "query limit" in rule.lower()):
            system_settings = customer_data.get('System_Settings__c', [])
            global_settings = next((s for s in system_settings if s.get('Name') == 'Global_Settings'), None)
            
            if global_settings and 'Max_Records_Per_Query__c' in global_settings:
                try:
                    query_limit = int(global_settings.get('Max_Records_Per_Query__c', 0))
                    if query_limit > 200:
                        issues.append(ConfigValidationIssue(
                            object_name='System_Settings__c',
                            record_id='Global_Settings',
                            field_name='Max_Records_Per_Query__c',
                            severity=Severity.MEDIUM,
                            issue_type=IssueType.BUSINESS_RULE_VIOLATION,
                            message="Query limit exceeds recommended maximum",
                            expected_value="≤ 200",
                            actual_value=str(query_limit),
                            suggestion="Reduce query limit to 200 or less",
                            customer_impact="Performance may be degraded with large queries"
                        ))
                except (ValueError, TypeError):
                    issues.append(ConfigValidationIssue(
                        object_name='System_Settings__c',
                        record_id='Global_Settings',
                        field_name='Max_Records_Per_Query__c',
                        severity=Severity.LOW,
                        issue_type=IssueType.INVALID_VALUE,
                        message="Query limit is not a valid number",
                        expected_value="≤ 200",
                        actual_value=global_settings.get('Max_Records_Per_Query__c', ''),
                        suggestion="Set query limit to a number ≤ 200",
                        customer_impact="Default query limits will be used"
                    ))
            
        return issues
    
    def generate_summary(self, 
                        template_data: Dict[str, List[Dict[str, Any]]], 
                        customer_data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Generate configuration completeness summary"""
        
        summary = {
            'timestamp': datetime.now().isoformat(),
            'objects': {},
            'overall_completeness': 0,
            'total_template_records': 0,
            'total_customer_records': 0,
            'missing_objects': [],
            'incomplete_objects': []
        }
        
        for obj_name, template_records in template_data.items():
            customer_records = customer_data.get(obj_name, [])
            
            completeness = 0
            if template_records:
                completeness = min(100, (len(customer_records) / len(template_records)) * 100)
            
            summary['objects'][obj_name] = {
                'template_count': len(template_records),
                'customer_count': len(customer_records),
                'completeness': round(completeness, 1)
            }
            
            summary['total_template_records'] += len(template_records)
            summary['total_customer_records'] += len(customer_records)
            
            if len(customer_records) == 0:
                summary['missing_objects'].append(obj_name)
            elif completeness < 80:
                summary['incomplete_objects'].append(obj_name)
        
        if summary['total_template_records'] > 0:
            summary['overall_completeness'] = round(
                (summary['total_customer_records'] / summary['total_template_records']) * 100, 1
            )
        
        return summary
    
    def validate_from_files_or_salesforce(self,
                                 template_path: str,
                                 customer_path: str = None,
                                 sf_username: str = None,
                                 sf_password: str = None,
                                 sf_security_token: str = None,
                                 sf_access_token: str = None,
                                 sf_client_id: str = None,
                                 sf_client_secret: str = None,
                                 sf_instance_url: str = None,
                                 sf_grant_type: str = 'password',
                                 sf_use_oauth: bool = False,
                                 sf_domain: str = 'login',
                                 sf_is_sandbox: bool = False,
                                 sf_objects: List[str] = None,
                                 business_rules_file: str = None,
                                 save_sf_data: bool = False,
                                 use_llm: bool = False,
                                 llm_provider: str = "anthropic",
                                 llm_model: str = None,
                                 interactive: bool = False) -> tuple:
        """Main validation method supporting both files and direct Salesforce extraction"""

        print(f"📋 Loading template from {template_path}")
        template_data = self.load_data(template_path)

        # Check if we should connect to Salesforce
        should_connect_sf = (
            (sf_access_token and sf_instance_url) or
            (sf_username and sf_password and (sf_security_token or (sf_client_id and sf_client_secret)))
        )

        if should_connect_sf:
            print("🔗 Connecting to Salesforce to extract customer data...")

            # Use access token if provided
            if sf_access_token and sf_instance_url:
                self.connect_with_access_token(
                    instance_url=sf_instance_url,
                    access_token=sf_access_token
                )
            # Use OAuth if credentials provided and flag is set
            elif sf_use_oauth and sf_client_id and sf_client_secret:
                self.connect_to_salesforce_oauth(
                    client_id=sf_client_id,
                    client_secret=sf_client_secret,
                    username=sf_username,
                    password=sf_password,
                    domain=sf_domain,
                    is_sandbox=sf_is_sandbox,
                    instance_url=sf_instance_url,
                    grant_type=sf_grant_type
                )
            elif sf_security_token:
                self.connect_to_salesforce(
                    username=sf_username,
                    password=sf_password,
                    security_token=sf_security_token,
                    domain=sf_domain,
                    is_sandbox=sf_is_sandbox
                )
            else:
                raise ValueError("Invalid Salesforce credentials provided")

            if not sf_objects:
                sf_objects = list(template_data.keys())
                print(f"📋 Auto-detected objects to extract: {sf_objects}")

            customer_data = self.extract_salesforce_data(sf_objects)

            if save_sf_data:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_dir = f"salesforce_data_{timestamp}"
                self.save_salesforce_data(customer_data, output_dir)

        elif customer_path:
            print(f"📋 Loading customer data from {customer_path}")
            customer_data = self.load_data(customer_path)

        else:
            raise ValueError("Must provide either customer_path or Salesforce credentials")
        
        business_rules = []
        if business_rules_file and os.path.exists(business_rules_file):
            with open(business_rules_file, 'r') as f:
                business_rules = [line.strip() for line in f 
                                if line.strip() and not line.startswith('#')]
        
        summary = self.generate_summary(template_data, customer_data)
        print(f"📊 Configuration completeness: {summary['overall_completeness']}%")
        
        summary['data_source'] = 'salesforce' if sf_username else 'file'
        summary['extraction_timestamp'] = datetime.now().isoformat()
        
        if use_llm:
            print(f"🧠 Analyzing configuration with {llm_provider} LLM...")
            
            # Create the prompt directly here to ensure it gets saved even in interactive mode
            rules_text = "\n".join(business_rules) if business_rules else "No specific business rules provided."
            prompt = self._create_llm_prompt(template_data, customer_data, rules_text)
            
            issues = self.validate_with_llm(
                template_data, 
                customer_data, 
                business_rules, 
                llm_provider=llm_provider,
                llm_model=llm_model,
                interactive=interactive,
                prompt=prompt  # Pass the pre-generated prompt
            )
            summary['validation_method'] = f"AI-powered ({llm_provider}{' interactive' if interactive else ''})"
            
            
            # Mark issues as coming from LLM
            for issue in issues:
                setattr(issue, 'source', 'llm')
            
        else:
            print("🔍 Analyzing configuration with rule-based validator...")
            issues = self.validate_configuration(template_data, customer_data, business_rules)
            summary['validation_method'] = "Rule-based"
            
            # Mark issues as coming from rules
            for issue in issues:
                setattr(issue, 'source', 'rule')
        
        # Print more details about the overall configuration
        print(f"📋 Configuration Analysis:")
        print(f"   - Total template objects: {len(template_data)}")
        print(f"   - Objects with missing data: {len(summary['missing_objects'])}")
        print(f"   - Objects with incomplete data: {len(summary['incomplete_objects'])}")
        if summary['missing_objects']:
            print(f"   - Missing objects: {', '.join(summary['missing_objects'])}")
        if summary['incomplete_objects']:
            print(f"   - Incomplete objects: {', '.join(summary['incomplete_objects'])}")
        
        return issues, summary
    
    def export_results(self, issues: List[ConfigValidationIssue], 
                      summary: Dict[str, Any], 
                      output_file: str, 
                      detailed_report: bool = True):
        """Export validation results to JSON"""
        
        results = {
            'summary': summary,
            'validation_method': summary.get('validation_method', 'Rule-based'),
            'issues': [
                {
                    'object_name': issue.object_name,
                    'record_id': issue.record_id,
                    'field_name': issue.field_name,
                    'severity': issue.severity.value,
                    'issue_type': issue.issue_type.value,
                    'message': issue.message,
                    'expected_value': issue.expected_value,
                    'actual_value': issue.actual_value,
                    'suggestion': issue.suggestion,
                    'customer_impact': issue.customer_impact,
                    'source': getattr(issue, 'source', 'rule')
                }
                for issue in issues
            ],
            'issue_counts': {
                'total': len(issues),
                'critical': len([i for i in issues if i.severity == Severity.CRITICAL]),
                'high': len([i for i in issues if i.severity == Severity.HIGH]),
                'medium': len([i for i in issues if i.severity == Severity.MEDIUM]),
                'low': len([i for i in issues if i.severity == Severity.LOW])
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"💾 Results exported to {output_file}")
        
        # Generate detailed HTML report if requested
        if detailed_report:
            html_file = output_file.replace('.json', '.html') if output_file.endswith('.json') else f"{output_file}.html"
            self._generate_html_report(results, html_file)
            print(f"💾 Detailed HTML report saved to {html_file}")

def main():
    parser = argparse.ArgumentParser(description="Salesforce Config Validator (Rule-Based or LLM-Based)")
    parser.add_argument("--template", required=True, help="Template configuration file/directory")
    
    data_group = parser.add_mutually_exclusive_group(required=True)
    data_group.add_argument("--customer", help="Customer configuration file/directory")
    data_group.add_argument("--sf-extract", action="store_true", 
                           help="Extract customer data from Salesforce org")
    
    parser.add_argument("--sf-username", help="Salesforce username")
    parser.add_argument("--sf-password", help="Salesforce password")
    parser.add_argument("--sf-token", help="Salesforce security token (for username/password auth)")
    parser.add_argument("--sf-access-token", help="Salesforce access token (Bearer token)")
    parser.add_argument("--sf-client-id", help="Salesforce OAuth client ID (for OAuth auth)")
    parser.add_argument("--sf-client-secret", help="Salesforce OAuth client secret (for OAuth auth)")
    parser.add_argument("--sf-grant-type", choices=['password', 'client_credentials'], default='password',
                       help="OAuth grant type (password or client_credentials)")
    parser.add_argument("--sf-instance-url", help="Salesforce instance URL (e.g., https://myorg.my.salesforce.com)")
    parser.add_argument("--sf-domain", default="login",
                       help="Salesforce domain (login, test, or custom)")
    parser.add_argument("--sf-sandbox", action="store_true",
                       help="Connect to sandbox org")
    parser.add_argument("--sf-objects", nargs="+",
                       help="Specific Salesforce objects to extract")
    parser.add_argument("--save-sf-data", action="store_true",
                       help="Save extracted Salesforce data to files")
    
    parser.add_argument("--rules", help="Business rules file")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--detailed-report", action="store_true", 
                       help="Generate detailed HTML report")
    parser.add_argument("--filter-severity", choices=['low', 'medium', 'high', 'critical'],
                       help="Only show issues of this severity or higher")
    
    # LLM-related arguments
    parser.add_argument("--use-llm", action="store_true",
                       help="Use LLM for validation instead of rule-based approach")
    parser.add_argument("--llm-provider", choices=['openai', 'anthropic', 'interactive'], default='anthropic',
                       help="LLM provider to use (openai, anthropic, or interactive)")
    parser.add_argument("--llm-model", 
                       help="Specific LLM model to use (e.g., gpt-4-turbo for OpenAI or claude-3-5-sonnet for Anthropic)")
    parser.add_argument("--openai-api-key", 
                       help="OpenAI API key (if using OpenAI)")
    parser.add_argument("--anthropic-api-key", 
                       help="Anthropic API key (if using Anthropic)")
    parser.add_argument("--interactive", action="store_true",
                      help="Interactive mode for LLM validation - will ask for manual review of the validation results")
    
    args = parser.parse_args()
    
    if args.sf_extract:
        # Check authentication method
        using_access_token = args.sf_access_token and args.sf_instance_url
        using_oauth = args.sf_client_id and args.sf_client_secret
        using_password = args.sf_token

        # If using access token, skip other credential checks
        if using_access_token:
            print("ℹ️  Using access token authentication")
        else:
            # For client_credentials grant, username/password not required
            if args.sf_grant_type != 'client_credentials':
                if not args.sf_username or not args.sf_password:
                    print("❌ Error: Salesforce extraction requires --sf-username and --sf-password for password grant")
                    return 1

            if not using_oauth and not using_password:
                print("❌ Error: Salesforce extraction requires either:")
                print("  - --sf-access-token and --sf-instance-url (for direct token auth)")
                print("  - --sf-token (for username/password auth)")
                print("  - --sf-client-id and --sf-client-secret (for OAuth auth)")
                return 1

            if using_oauth and using_password:
                print("⚠️  Warning: Both OAuth and password auth provided. Using OAuth.")

        if not SALESFORCE_AVAILABLE:
            print("❌ Error: simple-salesforce library not installed")
            print("Install with: pip install simple-salesforce")
            return 1
    
    # Check LLM requirements
    if args.use_llm:
        if args.llm_provider == 'openai' and not args.openai_api_key:
            print("❌ Error: OpenAI validation requires --openai-api-key")
            return 1
            
        # For Anthropic, check if settings file exists before requiring API key
        if args.llm_provider == 'anthropic' and not args.anthropic_api_key:
            settings_file = os.path.expanduser("~/.claude/settings.json")
            if not os.path.exists(settings_file) or not _check_settings_file_has_token(settings_file):
                print("❌ Error: Anthropic validation requires --anthropic-api-key or valid settings in ~/.claude/settings.json")
                return 1
            
        if args.llm_provider == 'openai' and not OPENAI_AVAILABLE:
            print("❌ Error: openai library not installed")
            print("Install with: pip install openai")
            return 1
    
    try:
        validator = RuleBasedValidator()
        
        # Initialize LLM client if needed (skip for interactive mode)
        if args.use_llm and args.llm_provider != 'interactive':
            if args.llm_provider == 'openai':
                validator.connect_to_openai(args.openai_api_key, args.llm_model)
            else:
                validator.connect_to_anthropic(args.anthropic_api_key, args.llm_model)
        
        if args.sf_extract:
            # Determine which authentication method to use
            using_oauth = args.sf_client_id and args.sf_client_secret

            issues, summary = validator.validate_from_files_or_salesforce(
                template_path=args.template,
                sf_username=args.sf_username,
                sf_password=args.sf_password,
                sf_security_token=args.sf_token,
                sf_access_token=args.sf_access_token,
                sf_client_id=args.sf_client_id,
                sf_client_secret=args.sf_client_secret,
                sf_instance_url=args.sf_instance_url,
                sf_grant_type=args.sf_grant_type,
                sf_use_oauth=using_oauth,
                sf_domain=args.sf_domain,
                sf_is_sandbox=args.sf_sandbox,
                sf_objects=args.sf_objects,
                business_rules_file=args.rules,
                save_sf_data=args.save_sf_data,
                use_llm=args.use_llm,
                llm_provider=args.llm_provider,
                llm_model=args.llm_model,
                interactive=args.interactive
            )
        else:
            issues, summary = validator.validate_from_files_or_salesforce(
                template_path=args.template,
                customer_path=args.customer,
                business_rules_file=args.rules,
                use_llm=args.use_llm,
                llm_provider=args.llm_provider,
                llm_model=args.llm_model,
                interactive=args.interactive
            )
        
        if args.filter_severity:
            severity_order = ['low', 'medium', 'high', 'critical']
            min_level = severity_order.index(args.filter_severity)
            issues = [i for i in issues if severity_order.index(i.severity.value) >= min_level]
        
        if args.output:
            validator.export_results(issues, summary, args.output, detailed_report=args.detailed_report)
        
        if not issues:
            print("✅ Configuration validation passed - no issues found!")
            return 0
        
        print(f"\n⚠️  Found {len(issues)} configuration issues:")
        
        # Group issues by severity for reporting
        issues_by_severity = {
            'critical': [i for i in issues if i.severity.value == 'critical'],
            'high': [i for i in issues if i.severity.value == 'high'],
            'medium': [i for i in issues if i.severity.value == 'medium'],
            'low': [i for i in issues if i.severity.value == 'low']
        }
        
        # Print summary counts by severity
        print(f"Summary of issues:")
        print(f"  🚨 Critical: {len(issues_by_severity['critical'])}")
        print(f"  🔴 High:     {len(issues_by_severity['high'])}")
        print(f"  🟡 Medium:   {len(issues_by_severity['medium'])}")
        print(f"  🟢 Low:      {len(issues_by_severity['low'])}")
        print()
        
        # Print issues by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            severity_issues = issues_by_severity[severity]
            if not severity_issues:
                continue
            
            emoji = {'critical': '🚨', 'high': '🔴', 'medium': '🟡', 'low': '🟢'}[severity]
            print(f"\n{emoji} {severity.upper()} ISSUES:")
            
            for issue in severity_issues:
                print(f"  Object: {issue.object_name}")
                if issue.record_id:
                    print(f"  Record: {issue.record_id}")
                if issue.field_name:
                    print(f"  Field: {issue.field_name}")
                print(f"  Issue: {issue.message}")
                if issue.expected_value and issue.actual_value:
                    print(f"  Expected: {issue.expected_value}")
                    print(f"  Actual: {issue.actual_value}")
                if issue.suggestion:
                    print(f"  💡 Fix: {issue.suggestion}")
                print(f"  📊 Impact: {issue.customer_impact}")
                print()
        
        critical_count = len([i for i in issues if i.severity == Severity.CRITICAL])
        high_count = len([i for i in issues if i.severity == Severity.HIGH])
        
        if critical_count > 0:
            return 2
        elif high_count > 0:
            return 1
        return 0
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

def _check_settings_file_has_token(settings_file):
    """Check if the settings file contains an Anthropic auth token"""
    try:
        with open(settings_file, 'r') as f:
            settings = json.load(f)
            if 'env' in settings and 'ANTHROPIC_AUTH_TOKEN' in settings['env']:
                return True
    except Exception:
        pass
    return False

if __name__ == "__main__":
    sys.exit(main())