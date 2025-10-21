import json
import requests
import os
from dotenv import load_dotenv
from typing import Dict, Any
from google import genai

load_dotenv(override = True)

def generate_prompt(prompt_engineering_technique: str, vulnerability: str, chat_context = '') -> str:
    '''
    Creates a prompt to ask an LLM to generate a correction patch using a specified prompt engineering technique.
    '''

    if not vulnerability.strip():
        raise ValueError('Vulnerability argument cannot be empty')

    footer = 'Your response should only contain the generated shell script. Nothing else.'

    match prompt_engineering_technique:
        case 'zero-shot' | 'cognitive-verifier':
            return f'''
Generate a safe, idempotent, auditable BASH shell script capable of correcting the following vulnerability: ({vulnerability}) once executed on a Pop!OS 22.04 operating system.
{footer}'''

        case 'cognitive-verifier-follow-up':
            return f'''
{chat_context}
---
Check the BASH shell script above. Once executed, is it capable of correcting the vulnerability ({vulnerability})? 
If so, return the sent BASH shell script without any additional modifications and/or commentaries.
If not, modify it, correcting it and making it so that it can actually fully correct the vulnerability once executed.
{footer}'''
        
        case 'role-prompting':
            return f'''
You are a senior linux systems security engineer.
Your job is to produce a safe, idempotent, auditable BASH shell script that remediates the following vulnerability: ({vulnerability}) when executed on a Pop!OS 22.04 operating system.
{footer}'''
        
        
        case 'chain-of-thought':
            return f''' 
Generate a safe, idempotent, auditable BASH shell script capable of correcting the following vulnerability: ({vulnerability}) once executed on a Pop!OS 22.04 operating system.
Your response MUST follow this exact structure, with each section clearly defined:

## 1. Vulnerability Analysis
- **Description:** Explain what the vulnerability is in simple terms.
- **Impact:** Describe the potential risks and impact if the vulnerability is exploited.
- **Detection:** Detail the specific commands or checks that can be used to confirm a system is currently vulnerable.

---

## 2. Remediation Plan
- **Strategy:** Describe the step-by-step plan to fix the vulnerability. Explain why this is the optimal approach.
- **Pre-flight Checks:** List the checks the script will perform before making any changes (e.g., verifying root privileges, checking if the fix is already applied).
- **Safety Measures:** Explain the safety mechanisms that will be included (e.g., backing up configuration files before modifying them).
- **Verification:** Describe how the script will confirm that the fix was successfully applied.

---

## 3. Generated BASH Script
Generate the final BASH script based on the plan above. The script MUST adhere to the following best practices:
- **Shebang:** Start with `#!/bin/bash`.
- **Error Handling:** Use `set -euo pipefail` to ensure the script exits immediately if a command fails.
- **Idempotency:** The script must be safe to run multiple times. If it detects the system is already secure, it should report that and exit gracefully.
- **Auditability & Logging:** Include clear `echo` statements for each major action (e.g., "Checking for vulnerability...", "Creating backup of /etc/ssh/sshd_config...", "Applying remediation...", "Verification complete.").
- **Comments:** Add detailed comments within the code explaining the purpose of each function or command block.

{footer}'''
        
        case _:
            raise ValueError(f'Invalid prompt_engineering_technique: {prompt_engineering_technique}')
        

def ask_deepseek(prompt: str, timeout = 200) -> dict:
    '''
    Send a prompt to DeepSeek API via OpenRouter.
    
    Returns:
        Dict with "status" ("OK" or "ERR"), containing "content" if "status" is "OK" 
        or "details" if "status" is "ERR". 
    '''

    API_URL = "https://openrouter.ai/api/v1/chat/completions"
    MODEL = "deepseek/deepseek-chat-v3.1:free"

    #Check for API key
    API_KEY = os.getenv('DEEPSEEK_API_KEY')
    if not API_KEY:
        return {'status': 'ERR', 
                'details': 'DEEPSEEK_API_KEY environment variable not set.'}

    headers = {'Authorization': f'Bearer {API_KEY}', 
               'Content-Type': 'application/json'}
    
    data = json.dumps({'model': MODEL, 
                       'messages': [{'role': 'user', 'content': prompt}],})

    try:
        response = requests.post(
            url = API_URL,
            headers = headers,
            data = data, 
            timeout = timeout
        )

        response.raise_for_status()

        if response.status_code == 200:
            return {'status': 'OK', 
                    'content': response.json()['choices'][0]['message']['content']}
        else:
            return {'status': 'ERR', 
                    'details': f'Error while retrieving API data. Status code: {response.status_code}'}
        
    except requests.exceptions.Timeout:
        return {'status': 'ERR', 
                'details': f'Request timeoud out after {timeout} seconds'}
    except requests.exceptions.RequestException as e:
        return {'status': 'ERR', 
                'details': f'Network error: {e}'}
    except json.JSONDecodeError:
        return {'status': 'ERR',
                'details': 'Failed to parse API response as JSON'}
    except Exception as e:
        return {'status': 'ERR',
                'details': f'Unexpeted error: {str(e)}'}



def ask_gemini(prompt: str, model: str) -> dict:
    '''
    Send a prompt to Gemini.

    Returns:
        Dict with "status" ("OK" or "ERR"), containing "content" if "status" is "OK" 
        or "details" if "status" is "ERR". 
    '''

    client = genai.Client()
    contents = prompt

    try:
        response = client.models.generate_content(model = model, contents = contents)
        return {
            'status': 'OK',
            'content': response.text
        }
    except Exception as e:
        return {
            'status': 'ERR',
            'details': f'Unexpected error: {str(e)}'
        }


def call_LLM(model: str, prompt: str) -> Dict[str, Any]:
    '''
    Sends a prompt to the specified LLM model.

    Returns:
        Dict with "status" ("OK" or "ERR"), containing "content" if "status" is "OK" 
        or "details" if "status" is "ERR". 
    '''

    match model:
        case 'deepseek-V3.1':
            return ask_deepseek(prompt)
        case 'gemini-2.5-flash':
            return ask_gemini(prompt, 'gemini-2.5-flash')
        case 'gemini-2.5-pro':
            return ask_gemini(prompt, 'gemini-2.5-pro')
        case _:
            raise ValueError(f'Unknown model: {model}')