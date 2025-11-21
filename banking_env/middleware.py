from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from security_agent.ai_detector import MiniLMSecurityAgent
from security_agent.csrf_detector import CSRFDetector
from security_agent.ssrf_detector import SSRFDetector
import json
import logging

logger = logging.getLogger(__name__)

class AISecurityMiddleware(MiddlewareMixin):

    def __init__(self, get_response):
        super().__init__(get_response)
        self.get_response = get_response
        
        # Ton agent AI existant
        self.security_agent = MiniLMSecurityAgent()

        # 🔥 Ajout des détecteurs CSRF & SSRF
        self.csrf_detector = CSRFDetector()
        self.ssrf_detector = SSRFDetector()

    def process_request(self, request):

        excluded_paths = ['/admin/', '/static/', '/media/']
        if any(request.path.startswith(path) for path in excluded_paths):
            return None
        
        try:
            request_data = {
                'path': request.path,
                'method': request.method,
                'query_params': dict(request.GET),
                'headers': dict(request.headers),
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'client_ip': self._get_client_ip(request),
                'user_session': self._get_user_session(request)
            }
            
            if request.method in ['POST', 'PUT', 'PATCH']:
                try:
                    if request.content_type == 'application/json':
                        request_data['post_data'] = json.loads(request.body)
                    else:
                        request_data['post_data'] = dict(request.POST)
                except:
                    request_data['post_data'] = str(request.body)

            # ---------------------------
            # 🔥 Analyse CSRF
            # ---------------------------
            csrf_result = self.csrf_detector.detect(request)
            if csrf_result["malicious"]:
                return self._block_request(request, {
                    "type": "CSRF Attack",
                    "detail": csrf_result["reason"]
                })

            # ---------------------------
            # 🔥 Analyse SSRF
            # ---------------------------
            ssrf_result = self.ssrf_detector.detect(request)
            if ssrf_result["malicious"]:
                return self._block_request(request, {
                    "type": "SSRF Attempt",
                    "detail": ssrf_result["reason"]
                })

            # ---------------------------
            # 🔥 Analyse IA (MiniLM)
            # ---------------------------
            ai_result = self.security_agent.analyze_request(request_data)
            
            logger.info(
                f"Security Analysis - IP: {request_data['client_ip']} "
                f"Path: {request.path} Risk: {ai_result['overall_risk_score']}"
            )
            
            if ai_result['is_malicious']:
                return self._block_request(request, {
                    "type": ai_result['threats_detected'][0]['type'],
                    "detail": ai_result['threats_detected'][0].get('description', '')
                })

        except Exception as e:
            logger.error(f"Erreur dans l'analyse de sécurité: {e}")
        
        return None

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')
    
    def _get_user_session(self, request):
        try:
            if hasattr(request, 'session'):
                return request.session
            elif hasattr(request, 'user') and request.user.is_authenticated:
                return {'_auth_user_id': str(request.user.id)}
            else:
                return None
        except Exception:
            return None
    
    def _block_request(self, request, threat_info):
        logger.warning(
            f"Requête bloquée - IP: {self._get_client_ip(request)} "
            f"Path: {request.path} "
            f"Threat: {threat_info['type']}"
        )
        
        return JsonResponse({
            'error': 'Accès refusé',
            'message': 'Activité suspecte détectée',
            'threat_type': threat_info["type"],
            'details': threat_info["detail"],
            'request_id': id(request),
            'security_action': 'BLOCKED'
        }, status=403)
