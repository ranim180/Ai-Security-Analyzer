import os
import django
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'projet_ds1.settings')
django.setup()

from security_agent.ai_detector import MiniLMSecurityAgent

def test_simple_idor():
    print("🎯 TEST IDOR SIMPLE - TOUT DOIT ÊTRE DÉTECTÉ")
    print("=" * 60)
    
    agent = MiniLMSecurityAgent()
    
    test_cases = [
        {
            'name': 'IDOR URL - User 1 accède User 2',
            'request': {
                'path': '/api/users/123/profile',
                'query_params': {},
                'post_data': {},
                'client_ip': '192.168.1.100',
                'user_session': {'_auth_user_id': '456'}
            }
        },
        {
            'name': 'IDOR URL - User accède son propre profil',
            'request': {
                'path': '/api/users/456/profile', 
                'query_params': {},
                'post_data': {},
                'client_ip': '192.168.1.100',
                'user_session': {'_auth_user_id': '456'}
            }
        },
        {
            'name': 'IDOR Param GET',
            'request': {
                'path': '/api/account',
                'query_params': {'user_id': '789'},
                'post_data': {},
                'client_ip': '192.168.1.100',
                'user_session': {'_auth_user_id': '456'}
            }
        },
        {
            'name': 'IDOR Param POST', 
            'request': {
                'path': '/api/update',
                'query_params': {},
                'post_data': {'user_id': '999'},
                'client_ip': '192.168.1.100',
                'user_session': {'_auth_user_id': '456'}
            }
        },
        {
            'name': 'Requête normale',
            'request': {
                'path': '/api/products',
                'query_params': {'page': '1'},
                'post_data': {'search': 'laptop'},
                'client_ip': '192.168.1.100',
                'user_session': {'_auth_user_id': '456'}
            }
        }
    ]
    
    for test_case in test_cases:
        print(f"\n🧪 {test_case['name']}")
        print(f"   URL: {test_case['request']['path']}")
        
        if test_case['request']['query_params']:
            print(f"   GET: {test_case['request']['query_params']}")
        if test_case['request']['post_data']:
            print(f"   POST: {test_case['request']['post_data']}")
        
        result = agent.analyze_request(test_case['request'])
        
        print(f"   🔍 Résultat: {'🚨 DÉTECTÉ' if result['is_malicious'] else '✅ AUTORISÉ'}")
        
        if result['threats_detected']:
            for threat in result['threats_detected']:
                print(f"      - {threat['type']} (confiance: {threat.get('confidence', 0):.2f})")
                if 'details' in threat:
                    print(f"        Raison: {threat['details'].get('reason', 'N/A')}")
        
        print(f"   📊 Score risque: {result['overall_risk_score']:.2f}")

if __name__ == '__main__':
    test_simple_idor()