# modules/ai_engine.py
# This module handles all AI interactions using the GitHub model API

import os
import json
from openai import OpenAI

class AIEngine:
    def __init__(self, model="openai/gpt-4.1"):
        self.endpoint = "https://models.github.ai/inference"
        self.model = model
        self.token = os.environ.get("GITHUB_TOKEN")
        if not self.token:
            raise ValueError("GITHUB_TOKEN environment variable is not set")
        self.client = OpenAI(
            base_url=self.endpoint,
            api_key=self.token,
        )

    def analyze_scan_results(self, url, recon_data, vuln_results):
        """
        Use AI to analyze scan results and provide additional insights
        """
        # Prepare context for AI
        scan_context = {
            "url": url,
            "recon_data": recon_data,
            "vulnerability_findings": vuln_results
        }
        # Check if there are no vulnerabilities
        no_vulns = False
        if not vuln_results or (isinstance(vuln_results, dict) and all((not v or v == [] or v is None) for k, v in vuln_results.items() if isinstance(v, list))):
            no_vulns = True
        # Create system prompt
        if no_vulns:
            system_prompt = ("You are Revisyn AI, an expert cybersecurity assistant specialized in web vulnerability assessment. "
                             "If there are no vulnerabilities found, simply and honestly state: 'No vulnerabilities were detected. This website appears to be safe (supposed).' Do not add any further analysis, recommendations, or speculation.")
        else:
            system_prompt = """You are Revisyn AI, an expert cybersecurity assistant specialized in web vulnerability assessment.
Analyze the provided scan results and identify:
1. Additional security vulnerabilities that might be present
2. Prioritization of discovered vulnerabilities based on severity
3. Recommended remediation steps for each vulnerability
4. Hidden relationships between the discovered vulnerabilities
5. Potential attack vectors that could exploit these vulnerabilities

Focus on providing actionable insights that would be valuable to a security professional.
Be specific and technical in your analysis. Provide explanations for your findings.
"""
        # Create user message with scan data
        user_message = f"Please analyze these scan results for {url}:\n\n{json.dumps(scan_context, indent=2)}"
        # Get AI response
        try:
            response = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ],
                temperature=0.2,  # Lower temperature for more focused answers
                top_p=0.95,
                model=self.model
            )
            analysis = response.choices[0].message.content
            return analysis
        except Exception as e:
            return f"AI analysis error: {str(e)}"

    def generate_exploit_proof_of_concept(self, vulnerability_data):
        """
        Generate a proof of concept for an identified vulnerability (for educational purposes only)
        """
        # Create a system prompt focused on safe, educational exploit examples
        system_prompt = """You are Revisyn AI, an expert cybersecurity assistant.
Generate a safe, educational proof-of-concept that demonstrates the vulnerability without causing actual harm.
Your code should be for educational purposes only and should include:
1. A clear explanation of how the vulnerability works
2. Code that demonstrates the vulnerability in a safe, controlled manner
3. Commentary explaining each step
4. How to fix the vulnerability

Never include code that would cause actual damage to systems or data.
"""
        
        # Create user message with vulnerability details
        user_message = f"Please create a safe proof of concept for this vulnerability:\n\n{json.dumps(vulnerability_data, indent=2)}"
        
        try:
            response = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ],
                temperature=0.3,
                top_p=0.95,
                model=self.model
            )
            
            poc = response.choices[0].message.content
            return poc
            
        except Exception as e:
            return f"Error generating proof of concept: {str(e)}"
    
    def analyze_web_technologies(self, tech_data):
        """
        Analyze detected web technologies for potential vulnerabilities
        """
        system_prompt = """You are Revisyn AI, an expert in web technology security assessment.
For each detected technology, provide:
1. Common vulnerabilities associated with this technology, especially for the detected version
2. Configuration best practices for security
3. Known CVEs that might apply
4. Specific security implications for this technology in the overall application architecture
"""
        
        user_message = f"Please analyze these web technologies detected in the scan:\n\n{json.dumps(tech_data, indent=2)}"
        
        try:
            response = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ],
                temperature=0.2,
                top_p=0.95,
                model=self.model
            )
            
            analysis = response.choices[0].message.content
            return analysis
            
        except Exception as e:
            return f"Error analyzing web technologies: {str(e)}"