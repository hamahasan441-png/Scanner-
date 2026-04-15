#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Local LLM Integration
Automatic download and inference using Qwen2.5-7B (GGUF quantized)
via llama-cpp-python.  Optimized for Termux (Android) and Linux.

Provides AI-powered:
  - Vulnerability analysis and finding enrichment
  - Payload suggestion based on target context
  - False positive reduction via response analysis
  - Scan summary and remediation generation

Usage:
  python main.py -t https://target.com --local-llm           # auto-download + use
  python main.py --download-model                             # download model only
  python main.py -t https://target.com --local-llm --llm-model /path/to/model.gguf
"""

import os
import sys
import json
import hashlib
import platform
import shutil
import time
from pathlib import Path


from config import Config, Colors


# ── Model Configuration ──────────────────────────────────────────────

# Default: Qwen2.5-7B-Instruct Q4_K_M quantization (~4.7 GB)
# Optimized for ARM (Termux) and x86-64 (Linux/Desktop)
DEFAULT_MODEL_REPO = "Qwen/Qwen2.5-7B-Instruct-GGUF"
DEFAULT_MODEL_FILE = "qwen2.5-7b-instruct-q4_k_m.gguf"
DEFAULT_MODEL_URL = (
    f"https://huggingface.co/{DEFAULT_MODEL_REPO}"
    f"/resolve/main/{DEFAULT_MODEL_FILE}"
)
DEFAULT_MODEL_SIZE_BYTES = 4_683_218_944  # ~4.7 GB approximate

# Directory to store downloaded models
MODELS_DIR = os.path.join(Config.BASE_DIR, "models")

# Inference defaults (tuned for security analysis on low-resource devices)
DEFAULT_CTX_SIZE = 2048
DEFAULT_MAX_TOKENS = 512
DEFAULT_TEMPERATURE = 0.3
DEFAULT_N_THREADS = max(1, (os.cpu_count() or 2) - 1)  # Leave 1 core free
DEFAULT_N_GPU_LAYERS = 0  # CPU-only by default for Termux


# ── Helper: Progress bar for downloads ────────────────────────────────

def _download_progress(current, total, bar_length=40):
    """Print a simple progress bar to stderr."""
    if total <= 0:
        return
    fraction = current / total
    filled = int(bar_length * fraction)
    bar = '█' * filled + '░' * (bar_length - filled)
    mb_current = current / (1024 * 1024)
    mb_total = total / (1024 * 1024)
    sys.stderr.write(
        f"\r  [{bar}] {fraction:.1%}  {mb_current:.0f}/{mb_total:.0f} MB"
    )
    sys.stderr.flush()
    if current >= total:
        sys.stderr.write('\n')


# ── Model Download ────────────────────────────────────────────────────

def get_model_path(model_file=None):
    """Return the local path for the GGUF model file."""
    fname = model_file or DEFAULT_MODEL_FILE
    return os.path.join(MODELS_DIR, fname)


def is_model_downloaded(model_file=None):
    """Check whether the GGUF model exists locally."""
    path = get_model_path(model_file)
    return os.path.isfile(path) and os.path.getsize(path) > 100_000_000


def download_model(model_url=None, model_file=None, force=False):
    """Download the Qwen2.5-7B GGUF model from HuggingFace.

    Uses ``requests`` (already a framework dependency) for the download
    with streaming to keep memory usage low — critical for Termux.

    Parameters
    ----------
    model_url : str, optional
        Full URL to the GGUF file.  Defaults to the official Qwen2.5-7B
        Instruct Q4_K_M hosted on HuggingFace.
    model_file : str, optional
        Local filename.  Defaults to ``qwen2.5-7b-instruct-q4_k_m.gguf``.
    force : bool
        Re-download even if the file already exists.

    Returns
    -------
    str
        Absolute path to the downloaded model file.
    """
    url = model_url or DEFAULT_MODEL_URL
    dest = get_model_path(model_file)

    if not force and is_model_downloaded(model_file):
        print(f"{Colors.success(f'Model already downloaded: {dest}')}")
        return dest

    os.makedirs(MODELS_DIR, exist_ok=True)

    print(f"{Colors.info('Downloading Qwen2.5-7B-Instruct GGUF model...')}")
    print(f"  Source : {url}")
    print(f"  Target : {dest}")
    print(f"  Size   : ~{DEFAULT_MODEL_SIZE_BYTES / (1024**3):.1f} GB")
    print()

    import requests  # framework core dependency

    tmp_path = dest + ".part"
    resume_size = 0
    headers = {}

    # Support resume for interrupted downloads
    if os.path.isfile(tmp_path):
        resume_size = os.path.getsize(tmp_path)
        headers['Range'] = f'bytes={resume_size}-'
        print(f"{Colors.info(f'Resuming from {resume_size / (1024**2):.0f} MB...')}")

    try:
        resp = requests.get(url, stream=True, headers=headers, timeout=60)
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"{Colors.error(f'Download failed: {exc}')}")
        print(f"{Colors.info('You can manually download the model:')}")
        print(f"  wget {url} -O {dest}")
        return ''

    total = int(resp.headers.get('content-length', 0)) + resume_size

    mode = 'ab' if resume_size else 'wb'
    try:
        with open(tmp_path, mode) as f:
            downloaded = resume_size
            for chunk in resp.iter_content(chunk_size=1024 * 1024):  # 1 MB chunks
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    _download_progress(downloaded, total)
    except (KeyboardInterrupt, Exception) as exc:
        print(f"\n{Colors.warning(f'Download interrupted: {exc}')}")
        print(f"{Colors.info(f'Partial file saved — re-run to resume.')}")
        return ''

    # Rename from .part to final name
    shutil.move(tmp_path, dest)
    print(f"\n{Colors.success(f'Model downloaded successfully: {dest}')}")
    return dest


# ── LLM Inference Engine ──────────────────────────────────────────────

class LocalLLM:
    """Local Qwen2.5-7B inference engine using llama-cpp-python.

    Automatically downloads the model on first use and provides
    security-focused analysis methods for the scan pipeline.
    """

    def __init__(self, model_path=None, n_ctx=None, n_threads=None,
                 n_gpu_layers=None, verbose=False):
        self.model_path = model_path or get_model_path()
        self.n_ctx = n_ctx or DEFAULT_CTX_SIZE
        self.n_threads = n_threads or DEFAULT_N_THREADS
        self.n_gpu_layers = n_gpu_layers if n_gpu_layers is not None else DEFAULT_N_GPU_LAYERS
        self.verbose = verbose
        self._llm = None  # Lazy-loaded

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @staticmethod
    def is_available():
        """Check whether llama-cpp-python is installed."""
        try:
            import llama_cpp  # noqa: F401
            return True
        except ImportError:
            return False

    @staticmethod
    def install_backend():
        """Install llama-cpp-python via pip.

        On Termux this compiles from source using clang.
        """
        print(f"{Colors.info('Installing llama-cpp-python (this may take a few minutes on Termux)...')}")
        import subprocess
        env = os.environ.copy()
        # Termux-specific: ensure clang is used as the C compiler
        if 'com.termux' in os.environ.get('PREFIX', ''):
            env.setdefault('CC', 'clang')
            env.setdefault('CXX', 'clang++')
        try:
            subprocess.check_call(
                [sys.executable, '-m', 'pip', 'install',
                 'llama-cpp-python', '--no-cache-dir'],
                env=env,
            )
            print(f"{Colors.success('llama-cpp-python installed successfully.')}")
            return True
        except subprocess.CalledProcessError as exc:
            print(f"{Colors.error(f'Installation failed: {exc}')}")
            print(f"{Colors.info('Manual install:  pip install llama-cpp-python')}")
            return False

    def ensure_ready(self):
        """Ensure backend is installed and model is downloaded.

        Returns True when inference is possible, False otherwise.
        """
        # 1. Check / install backend
        if not self.is_available():
            print(f"{Colors.warning('llama-cpp-python not installed.')}")
            ok = self.install_backend()
            if not ok:
                return False

        # 2. Check / download model
        if not os.path.isfile(self.model_path):
            path = download_model()
            if not path:
                return False
            self.model_path = path

        return True

    def load(self):
        """Load the model into memory."""
        if self._llm is not None:
            return True

        if not self.ensure_ready():
            return False

        try:
            from llama_cpp import Llama

            print(f"{Colors.info(f'Loading Qwen2.5-7B model ({self.n_threads} threads, ctx={self.n_ctx})...')}")
            start = time.time()
            self._llm = Llama(
                model_path=self.model_path,
                n_ctx=self.n_ctx,
                n_threads=self.n_threads,
                n_gpu_layers=self.n_gpu_layers,
                verbose=self.verbose,
            )
            elapsed = time.time() - start
            print(f"{Colors.success(f'Model loaded in {elapsed:.1f}s')}")
            return True
        except Exception as exc:
            print(f"{Colors.error(f'Failed to load model: {exc}')}")
            self._llm = None
            return False

    def unload(self):
        """Release model from memory."""
        self._llm = None

    @property
    def is_loaded(self):
        return self._llm is not None

    # ------------------------------------------------------------------
    # Core inference
    # ------------------------------------------------------------------

    def _generate(self, prompt, max_tokens=None, temperature=None, stop=None):
        """Raw text generation with the local model.

        Returns the generated text string, or empty string on failure.
        """
        if not self.is_loaded:
            if not self.load():
                return ''

        max_tokens = max_tokens or DEFAULT_MAX_TOKENS
        temperature = temperature if temperature is not None else DEFAULT_TEMPERATURE

        try:
            result = self._llm(
                prompt,
                max_tokens=max_tokens,
                temperature=temperature,
                stop=stop or ['<|im_end|>', '<|endoftext|>'],
                echo=False,
            )
            text = result['choices'][0]['text'].strip() if result.get('choices') else ''
            return text
        except Exception as exc:
            if self.verbose:
                print(f"{Colors.error(f'LLM inference error: {exc}')}")
            return ''

    def chat(self, system_prompt, user_message, max_tokens=None, temperature=None):
        """Send a chat-formatted message to the model.

        Uses Qwen2.5's ChatML template:
          <|im_start|>system\n{system}<|im_end|>
          <|im_start|>user\n{user}<|im_end|>
          <|im_start|>assistant\n
        """
        prompt = (
            f"<|im_start|>system\n{system_prompt}<|im_end|>\n"
            f"<|im_start|>user\n{user_message}<|im_end|>\n"
            f"<|im_start|>assistant\n"
        )
        return self._generate(
            prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            stop=['<|im_end|>', '<|endoftext|>'],
        )

    # ------------------------------------------------------------------
    # Security Analysis Methods
    # ------------------------------------------------------------------

    def analyze_finding(self, finding_dict):
        """Analyze a vulnerability finding and provide enriched assessment.

        Parameters
        ----------
        finding_dict : dict
            Finding data with keys: technique, url, param, payload,
            evidence, severity, confidence.

        Returns
        -------
        dict
            Enriched analysis with keys: risk_assessment, exploitation_notes,
            remediation, false_positive_likelihood.
        """
        system = (
            "You are an expert penetration tester and application security "
            "analyst. Analyze the following vulnerability finding and provide "
            "a concise assessment. Be precise and technical."
        )
        user = (
            f"Vulnerability: {finding_dict.get('technique', 'Unknown')}\n"
            f"URL: {finding_dict.get('url', 'N/A')}\n"
            f"Parameter: {finding_dict.get('param', 'N/A')}\n"
            f"Payload: {finding_dict.get('payload', 'N/A')[:200]}\n"
            f"Evidence: {finding_dict.get('evidence', 'N/A')[:200]}\n"
            f"Severity: {finding_dict.get('severity', 'N/A')}\n"
            f"Confidence: {finding_dict.get('confidence', 'N/A')}\n\n"
            "Provide:\n"
            "1. Risk assessment (1-2 sentences)\n"
            "2. Exploitation notes (what an attacker could do)\n"
            "3. Remediation recommendation\n"
            "4. False positive likelihood (low/medium/high) with reason"
        )
        response = self.chat(system, user, max_tokens=400)
        return {
            'llm_analysis': response,
            'model': 'qwen2.5-7b-instruct-q4_k_m',
        }

    def suggest_payloads(self, vuln_type, context_info):
        """Suggest targeted payloads based on vulnerability context.

        Parameters
        ----------
        vuln_type : str
            Vulnerability category (sqli, xss, lfi, cmdi, etc.).
        context_info : dict
            Context with keys: technology, waf_detected, param_name,
            sample_response, etc.

        Returns
        -------
        list[str]
            List of suggested payload strings.
        """
        system = (
            "You are an expert in web application security testing. "
            "Generate targeted payloads for the specified vulnerability type "
            "based on the given context. Return ONLY the payloads, one per "
            "line, no explanations. Maximum 5 payloads."
        )
        tech = context_info.get('technology', 'unknown')
        waf = context_info.get('waf_detected', 'none')
        param = context_info.get('param_name', 'id')
        user = (
            f"Vulnerability type: {vuln_type}\n"
            f"Technology stack: {tech}\n"
            f"WAF detected: {waf}\n"
            f"Parameter name: {param}\n\n"
            "Generate 5 effective payloads for this context:"
        )
        response = self.chat(system, user, max_tokens=300, temperature=0.5)
        if not response:
            return []
        # Parse payloads (one per line, strip empty)
        payloads = [
            line.strip().lstrip('0123456789.-) ')
            for line in response.strip().split('\n')
            if line.strip() and not line.strip().startswith('#')
        ]
        return payloads[:5]

    def analyze_response(self, url, param, payload, response_snippet):
        """Analyze an HTTP response for vulnerability indicators.

        Helps reduce false positives by having the LLM assess whether
        a response actually indicates a vulnerability.

        Returns
        -------
        dict
            Analysis with 'is_vulnerable' (bool), 'confidence' (float),
            'reasoning' (str).
        """
        system = (
            "You are a security response analyzer. Given an HTTP response "
            "snippet after injecting a test payload, determine if the "
            "response indicates a real vulnerability or a false positive. "
            "Be conservative — only confirm if evidence is strong."
        )
        user = (
            f"URL: {url}\n"
            f"Parameter: {param}\n"
            f"Payload: {payload[:200]}\n"
            f"Response snippet (first 500 chars):\n"
            f"{response_snippet[:500]}\n\n"
            "Is this a real vulnerability? Answer with:\n"
            "VULNERABLE: yes/no\n"
            "CONFIDENCE: 0.0-1.0\n"
            "REASON: brief explanation"
        )
        response = self.chat(system, user, max_tokens=200, temperature=0.1)

        result = {'is_vulnerable': False, 'confidence': 0.0, 'reasoning': response}
        if not response:
            return result

        response_lower = response.lower()
        if 'vulnerable: yes' in response_lower:
            result['is_vulnerable'] = True
        # Parse confidence
        for line in response.split('\n'):
            if 'confidence:' in line.lower():
                try:
                    val = float(line.split(':')[-1].strip())
                    result['confidence'] = max(0.0, min(1.0, val))
                except (ValueError, IndexError):
                    pass
                break

        return result

    def generate_scan_summary(self, findings, target, scan_duration):
        """Generate a natural language scan summary report.

        Parameters
        ----------
        findings : list[dict]
            List of finding dictionaries from the scan.
        target : str
            The scanned target URL.
        scan_duration : float
            Total scan time in seconds.

        Returns
        -------
        str
            Human-readable scan summary.
        """
        # Aggregate findings by severity
        severity_counts = {}
        techniques = []
        for f in findings[:20]:  # Limit to keep within context window
            sev = f.get('severity', 'UNKNOWN')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            tech = f.get('technique', 'Unknown')
            if tech not in techniques:
                techniques.append(tech)

        system = (
            "You are a security consultant writing a professional "
            "vulnerability assessment summary. Be concise and actionable."
        )
        user = (
            f"Target: {target}\n"
            f"Scan duration: {scan_duration:.0f} seconds\n"
            f"Total findings: {len(findings)}\n"
            f"Severity breakdown: {json.dumps(severity_counts)}\n"
            f"Vulnerability types found: {', '.join(techniques[:10])}\n\n"
            "Write a professional executive summary (max 200 words) covering:\n"
            "1. Overall security posture\n"
            "2. Critical risks identified\n"
            "3. Top 3 priority remediation actions"
        )
        return self.chat(system, user, max_tokens=400)

    def classify_parameter(self, param_name, param_value, url):
        """Classify a parameter's likely purpose and vulnerability surface.

        Returns
        -------
        dict
            Classification with 'purpose', 'likely_vulns', 'priority'.
        """
        system = (
            "You are a security parameter classifier. Given a URL parameter, "
            "classify its purpose and likely vulnerability surface. "
            "Be concise. Return JSON only."
        )
        user = (
            f"URL: {url}\n"
            f"Parameter name: {param_name}\n"
            f"Sample value: {param_value[:100]}\n\n"
            "Return JSON: {{\"purpose\": \"...\", \"likely_vulns\": [\"sqli\", ...], \"priority\": \"high/medium/low\"}}"
        )
        response = self.chat(system, user, max_tokens=150, temperature=0.1)
        try:
            # Try to parse JSON from response
            start = response.find('{')
            end = response.rfind('}') + 1
            if start >= 0 and end > start:
                return json.loads(response[start:end])
        except (json.JSONDecodeError, ValueError):
            pass
        return {'purpose': 'unknown', 'likely_vulns': [], 'priority': 'medium'}

    def analyze_waf_strategy(self, waf_name, vuln_type, blocked_payloads):
        """Generate WAF bypass strategy based on blocked payloads.

        Parameters
        ----------
        waf_name : str
            Detected WAF name (e.g. 'cloudflare', 'modsecurity').
        vuln_type : str
            Vulnerability type being tested.
        blocked_payloads : list[str]
            Payloads that were blocked by the WAF.

        Returns
        -------
        dict
            Strategy with 'bypass_payloads', 'encoding_hints', 'notes'.
        """
        system = (
            "You are a WAF bypass expert. Given a WAF name and blocked "
            "payloads, suggest bypass techniques. Return ONLY bypass "
            "payloads, one per line. No explanations."
        )
        blocked_sample = '\n'.join(blocked_payloads[:5])
        user = (
            f"WAF: {waf_name}\n"
            f"Vulnerability type: {vuln_type}\n"
            f"Blocked payloads:\n{blocked_sample}\n\n"
            "Generate 5 bypass payloads that may evade this WAF:"
        )
        response = self.chat(system, user, max_tokens=300, temperature=0.5)
        if not response:
            return {'bypass_payloads': [], 'encoding_hints': [], 'notes': ''}

        payloads = [
            line.strip().lstrip('0123456789.-) ')
            for line in response.strip().split('\n')
            if line.strip() and not line.strip().startswith('#')
        ]
        return {
            'bypass_payloads': payloads[:5],
            'encoding_hints': [],
            'notes': f'AI-generated bypass for {waf_name}',
        }

    def prioritize_next_test(self, findings_so_far, remaining_modules):
        """Recommend which module to test next based on findings.

        Parameters
        ----------
        findings_so_far : list[dict]
            Findings discovered so far in the scan.
        remaining_modules : list[str]
            Module names not yet executed.

        Returns
        -------
        list[str]
            Reordered module list with highest-priority first.
        """
        if not remaining_modules:
            return remaining_modules

        system = (
            "You are a penetration testing strategist. Given current "
            "findings, recommend the optimal order to test remaining "
            "vulnerability modules. Return module names one per line, "
            "highest priority first. Only return names from the provided list."
        )
        found_types = list({f.get('technique', '') for f in findings_so_far[:10]})
        user = (
            f"Findings so far: {', '.join(found_types) if found_types else 'none'}\n"
            f"Remaining modules: {', '.join(remaining_modules)}\n\n"
            "Return the optimal test order (one module per line):"
        )
        response = self.chat(system, user, max_tokens=200, temperature=0.1)
        if not response:
            return remaining_modules

        # Parse recommended order
        suggested = []
        remaining_set = set(remaining_modules)
        for line in response.strip().split('\n'):
            name = line.strip().lower().rstrip('.,;')
            # Fuzzy match against remaining modules
            for mod in remaining_set:
                if mod.lower() in name or name in mod.lower():
                    if mod not in suggested:
                        suggested.append(mod)
                    break
        # Append any modules not mentioned
        for mod in remaining_modules:
            if mod not in suggested:
                suggested.append(mod)
        return suggested

    def batch_analyze_findings(self, findings):
        """Analyze multiple findings in a single LLM call for efficiency.

        Parameters
        ----------
        findings : list[dict]
            List of finding dictionaries.

        Returns
        -------
        str
            Combined analysis text.
        """
        system = (
            "You are a security analyst. Analyze these vulnerability "
            "findings as a group. Identify patterns, attack chains, "
            "and prioritized remediation. Be concise."
        )
        summary_lines = []
        for i, f in enumerate(findings[:10], 1):
            summary_lines.append(
                f"{i}. {f.get('technique', 'Unknown')} at {f.get('url', 'N/A')} "
                f"(param={f.get('param', 'N/A')}, severity={f.get('severity', 'N/A')})"
            )
        user = (
            f"Findings:\n" + '\n'.join(summary_lines) + "\n\n"
            "Provide:\n"
            "1. Attack chain opportunities\n"
            "2. Most critical finding and why\n"
            "3. Top 3 remediation priorities"
        )
        return self.chat(system, user, max_tokens=500)


# ── Standalone CLI entrypoint ─────────────────────────────────────────

def main():
    """Standalone model management CLI."""
    import argparse
    parser = argparse.ArgumentParser(description='ATOMIC Local LLM Manager')
    parser.add_argument('--download', action='store_true',
                        help='Download the Qwen2.5-7B GGUF model')
    parser.add_argument('--status', action='store_true',
                        help='Show model and backend status')
    parser.add_argument('--test', action='store_true',
                        help='Run a quick inference test')
    parser.add_argument('--model', type=str, default=None,
                        help='Path to custom GGUF model file')
    args = parser.parse_args()

    if args.status:
        print(f"Backend (llama-cpp-python): {'✓ installed' if LocalLLM.is_available() else '✗ not installed'}")
        path = get_model_path(args.model)
        print(f"Model path: {path}")
        print(f"Model downloaded: {'✓ yes' if is_model_downloaded(args.model) else '✗ no'}")
        if is_model_downloaded(args.model):
            size_gb = os.path.getsize(path) / (1024 ** 3)
            print(f"Model size: {size_gb:.2f} GB")
        print(f"Platform: {platform.system()} {platform.machine()}")
        print(f"CPU threads: {DEFAULT_N_THREADS}")
        return

    if args.download:
        download_model()
        return

    if args.test:
        llm = LocalLLM(model_path=args.model, verbose=True)
        if not llm.load():
            sys.exit(1)
        print("\n--- Test: Vulnerability Analysis ---")
        result = llm.analyze_finding({
            'technique': 'SQL Injection (Error-based)',
            'url': 'https://example.com/search?q=test',
            'param': 'q',
            'payload': "' OR 1=1 --",
            'evidence': 'MySQL syntax error detected',
            'severity': 'HIGH',
            'confidence': 0.9,
        })
        print(result.get('llm_analysis', 'No response'))
        print("\n--- Test complete ---")
        return

    parser.print_help()


if __name__ == '__main__':
    main()
