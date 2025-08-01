'''
# Cyber Threat Actor Research Prompt

**Research Target:** [INSERT THREAT ACTOR NAME/APT GROUP]

## Research Objectives

Conduct comprehensive research on the specified threat actor to produce a detailed intelligence report covering their tactics, techniques, procedures, recent activities, and threat landscape implications.

## Required Research Areas

### 1. Threat Actor Profile & TTPs
- **Group Overview:** Official designations, aliases, suspected attribution
- **Tactics, Techniques & Procedures (TTPs):** Map to MITRE ATT&CK framework
- **Primary Tooling:** Custom malware, commodity tools, living-off-the-land techniques
- **Motivation & Objectives:** Financial gain, espionage, disruption, ideology, state-sponsored activities
- **Operational Characteristics:** Attack patterns, victim selection criteria, operational security practices

### 2. Recent Activities Analysis (Last 12 Months)
Create a table with the following columns for each significant incident:

| Date | Target/Victim | Attack Summary | Initial Access | Persistence | Execution | Financial Impact | Tools/Malware Used |
|------|---------------|----------------|----------------|-------------|-----------|------------------|-------------------|
| [Date] | [Organization/Sector] | [Brief description] | [MITRE Technique] | [MITRE Technique] | [MITRE Technique] | [$ Amount if known] | [Specific tools] |

**For each incident, provide:**
- Detailed attack timeline and methodology
- MITRE ATT&CK technique mappings for each phase
- Specific malware families or tools employed
- Data exfiltration methods and scope
- Estimated financial damages or losses
- Attribution confidence level

### 3. Technical Indicators & Artifacts
- **Indicators of Compromise (IoCs):**
  - File hashes (MD5, SHA-1, SHA-256)
  - IP addresses and domains
  - Registry keys and file paths
  - Network signatures
  - Email indicators
- **Malware Analysis:**
  - Malware family names and variants
  - Command and control infrastructure
  - Persistence mechanisms
  - Evasion techniques
- **Infrastructure Analysis:**
  - Hosting providers and registrars
  - Domain registration patterns
  - Infrastructure reuse patterns

### 4. Targeting Patterns & Victimology
- **Geographic Distribution:** Countries and regions targeted
- **Sector Analysis:** Industries and organization types
- **Victim Characteristics:** Common attributes of targeted entities
- **Timeline Analysis:** Evolution of targeting over time

### 5. Threat Assessment & Predictions
- **Current Threat Level:** Assessment of ongoing activity
- **Future Targeting Predictions:** 
  - Likely next targets (sectors/regions)
  - Emerging attack vectors
  - Potential escalation scenarios
  - **Disclaimer:** *These predictions are based on available intelligence and historical patterns. Actual threat actor behavior may vary, and assessments should be considered analytical judgments rather than definitive forecasts.*

### 6. Defensive Recommendations
Provide 3-5 actionable recommendations:
1. **Detection & Monitoring:** Specific indicators to monitor
2. **Prevention Controls:** Technical and procedural safeguards
3. **Incident Response:** Preparation strategies for potential attacks
4. **Threat Hunting:** Proactive search strategies
5. **Intelligence Sharing:** Relevant information sharing initiatives

## Research Sources
- Open source intelligence (OSINT)
- Threat intelligence platforms
- Security vendor reports
- Government advisories
- Academic research
- Industry incident reports

## Deliverable Format
- Executive summary (1-2 pages)
- Detailed technical analysis
- Visual timeline of recent activities
- IoC appendix with machine-readable formats
- Reference list with source credibility assessment

## Quality Standards
- Verify information across multiple sources
- Distinguish between confirmed facts and analytical assessments
- Provide confidence levels for key judgments
- Include source attribution and publication dates
- Highlight any information gaps or limitations
'''