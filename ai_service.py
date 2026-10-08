"""
AI Service — all Claude API calls run here on the server
API key never touches the browser
"""
import anthropic, os
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY", ""))

def call(prompt: str, system: str, max_tokens: int = 1024) -> str:
    try:
        msg = client.messages.create(
            model      = "claude-sonnet-4-6",
            max_tokens = max_tokens,
            system     = system,
            messages   = [{"role": "user", "content": prompt}],
        )
        return msg.content[0].text
    except Exception as e:
        return f"AI error: {str(e)}"

SYSTEM = "You are the Apex Safari elite bug bounty AI. Be concise, technical and practical."

def generate_test_question(step_title: str, topics: list, level: str) -> dict:
    r = call(
        f"Generate a unique practical bug bounty question for a {level} hunter.\n"
        f"Topic: {step_title}. Subtopics: {', '.join(topics[:4])}.\n"
        f"Ask about a real-world scenario requiring specific Kali Linux commands.\n"
        f"Format:\nQUESTION: [question]\nHINT: [one real Kali command]",
        "You are an elite cybersecurity exam generator. Create challenging unique questions testing real hacking knowledge."
    )
    q, hint = r, ""
    if "HINT:" in r:
        parts = r.split("HINT:")
        q     = parts[0].replace("QUESTION:","").strip()
        hint  = parts[1].strip()
    elif "QUESTION:" in r:
        q = r.replace("QUESTION:","").strip()
    return {"question": q, "hint": hint, "step": step_title}

def grade_answer(step: str, question: str, answer: str) -> dict:
    import re
    r = call(
        f"Grade this bug bounty answer strictly:\nTopic: {step}\nQuestion: {question}\nAnswer: {answer or '[No answer]'}\n\n"
        f"SCORE: [0-10]\nVERDICT: [PASS or FAIL]\nFEEDBACK: [2 sentences]\nTIP: [one expert tip]",
        "You are a strict cybersecurity examiner. PASS = score 6+. FAIL = below 6."
    )
    score, verdict = 0, "FAIL"
    sm = re.search(r"SCORE:\s*(\d+)", r)
    vm = re.search(r"VERDICT:\s*(PASS|FAIL)", r)
    if sm: score   = min(10, int(sm.group(1)))
    if vm: verdict = vm.group(1)
    return {"score": score, "verdict": verdict, "feedback": r}

def analyze_scope(program: str, platform: str, screenshot_count: int) -> str:
    return call(
        f"Bug bounty scope analysis for {program} on {platform}. {screenshot_count} screenshots uploaded.\n\n"
        f"Provide:\n🗺️ ATTACK SURFACE MAP\n🚫 OUT OF SCOPE\n🎯 HIGH VALUE TARGETS\n"
        f"🔧 RECON COMMANDS (subfinder, nmap, ffuf, nuclei, httpx with real syntax)\n"
        f"💰 VULNERABILITY PRIORITIES\n🔮 BOUNTY ESTIMATE",
        "You are an elite bug bounty intelligence AI. Give specific real Kali commands.",
        max_tokens=2000
    )

def predict_bounty(vuln: str, severity: str, program: str, platform: str, description: str) -> str:
    return call(
        f"Predict bounty payout:\nVuln: {vuln}\nSeverity: {severity}\nProgram: {program}\nPlatform: {platform}\nDesc: {description}\n\n"
        f"MINIMUM: $[amount]\nEXPECTED: $[amount]\nMAXIMUM: $[amount]\nCONFIDENCE: [%]\nREASONING: [2 sentences]\nSIMILAR FINDINGS: [2-3 real examples]",
        "You are an expert bug bounty market analyst with deep knowledge of payout ranges."
    )

def check_duplicate(vuln: str, target: str, description: str) -> str:
    return call(
        f"Check duplicate risk:\nVuln: {vuln}\nTarget: {target}\nDesc: {description}\n\n"
        f"DUPLICATE_RISK: [LOW/MEDIUM/HIGH/CRITICAL]\nSIMILARITY: [%]\nREASONING: [why]\nRECOMMENDATION: [what to do]\nBYPASS_TIP: [if high risk]",
        "You are an elite bug bounty duplicate detection AI with knowledge of thousands of public disclosures."
    )

def write_report(vuln: str, target: str, steps: str, impact: str, poc: str, severity: str) -> str:
    return call(
        f"Write professional bug bounty report:\nVuln: {vuln}\nTarget: {target}\nSeverity: {severity}\n"
        f"Steps: {steps}\nImpact: {impact}\nPoC: {poc}\n\n"
        f"Include: TITLE, SEVERITY+CVSS, SUMMARY, DESCRIPTION, STEPS TO REPRODUCE, PROOF OF CONCEPT, IMPACT, REMEDIATION, REFERENCES",
        "You are an expert bug bounty report writer. Create professional compelling reports.",
        max_tokens=2000
    )

def chat(message: str, history: list) -> str:
    try:
        msg = client.messages.create(
            model    = "claude-sonnet-4-6",
            max_tokens=1024,
            system   = "You are the Apex Safari elite AI hunting assistant. Help with recon, vulnerabilities, exploitation, reporting, tools, and bounty strategy. Give real actionable technical advice with actual commands.",
            messages = history + [{"role": "user", "content": message}],
        )
        return msg.content[0].text
    except Exception as e:
        return f"AI error: {str(e)}"

def get_intelligence(intel_type: str) -> str:
    prompts = {
        "threats":  "Generate live threat intelligence for bug bounty hunters. List 5 active threats with CVE IDs, severity, affected systems, and recommended action.",
        "bounties": "Bug bounty market intel: top 5 highest paying programs now with amounts, most lucrative vuln classes, programs with lowest competition, 3 newly launched programs.",
        "trends":   "Top attack technique trends for bug bounty hunters. What vulnerability classes are trending? Where are biggest bounties being paid?",
        "cve":      "List 5 critical CVEs relevant to bug bounty hunters now. For each: CVE ID, CVSS, affected software, exploit status, exact Kali command to test.",
        "news":     "5 important cybersecurity news stories for bug bounty hunters. What happened, why it matters, what hunting opportunity it creates.",
        "surface":  "Attack surface intel for E-commerce, Banking, SaaS, Mobile, Cloud. For each: best tools, most common vulns found, recommended approach.",
    }
    return call(prompts.get(intel_type, "Provide general bug bounty intelligence."), SYSTEM, max_tokens=1500)

def learning_module(step_title: str, topics: list, is_weak: bool) -> str:
    return call(
        f"Create a bug bounty learning module{'— this hunter is WEAK here, be extra detailed' if is_weak else ''}.\n"
        f"Topic: {step_title}\nSubtopics: {', '.join(topics)}\n\n"
        f"📖 CONCEPT (2 paragraphs)\n🔧 KEY TECHNIQUES (5 with explanations)\n💻 KALI COMMANDS (real terminal commands)\n"
        f"🌍 REAL SCENARIO (realistic bug bounty example)\n🏋️ PRACTICE EXERCISE (specific task)\n💡 PRO TIPS (3 expert tips)",
        "You are an elite bug bounty training instructor. Be practical and immediately actionable.",
        max_tokens=2000
    )

def admin_insights(stats: dict) -> str:
    return call(
        f"Apex Safari platform insights for Larry Phillip Ochieng, CEO of Safari Intelligence:\nStats: {stats}\n\n"
        f"Give direct recommendations:\n1. Top 3 revenue actions this month\n2. Hunter retention strategies\n3. Features to build next\n4. Security concerns\n5. Platform adjustments",
        "You are the Apex Safari AI advisor for Larry Phillip Ochieng, founder of Safari Intelligence."
    )
