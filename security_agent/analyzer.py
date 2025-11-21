# security_agent/analyzer.py
from .ai_detector import AIDetector
from .csrf_detector import CSRFDetector
from .ssrf_detector import SSRFDetector

class SecurityAnalyzer:

    def __init__(self):
        self.ai_detector = AIDetector()
        self.csrf_detector = CSRFDetector()
        self.ssrf_detector = SSRFDetector()

    def analyze(self, request):
        """
        Analyse la requête via tous les modules :
        - AI model (MiniLM)
        - CSRF rules
        - SSRF rules
        Retourne un dict contenant les résultats.
        """

        results = {}

        # 1) Analyse IA (payload, header, URL)
        results["ai"] = self.ai_detector.analyze_request(request)

        # 2) Protection CSRF personnalisée
        results["csrf"] = self.csrf_detector.detect(request)

        # 3) Protection SSRF personnalisée
        results["ssrf"] = self.ssrf_detector.detect(request)

        # Si un module dit "malicious", on bloque
        results["is_malicious"] = (
            results["ai"]["malicious"]
            or results["csrf"]["malicious"]
            or results["ssrf"]["malicious"]
        )

        results["reason"] = (
            results["ai"].get("reason")
            or results["csrf"].get("reason")
            or results["ssrf"].get("reason")
        )

        return results
