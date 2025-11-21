import os
import django
import sys
import logging

# Configurez le logging pour voir les détails
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Ajoutez le chemin du projet
project_path = os.path.dirname(os.path.abspath(__file__))
sys.path.append(project_path)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'projet_ds1.settings')

try:
    django.setup()
    print("✅ Django configuré avec succès")
except Exception as e:
    print(f"❌ Erreur configuration Django: {e}")
    sys.exit(1)

from security_agent.ai_detector import MiniLMSecurityAgent

def debug_agent():
    print("🔧 Initialisation de l'agent de sécurité...")
    
    try:
        agent = MiniLMSecurityAgent()
        print("✅ Agent initialisé avec succès")
    except Exception as e:
        print(f"❌ Erreur initialisation agent: {e}")
        return
    
    test_cases = [
        {
            'name': 'SQL Injection simple',
            'request': {
                'path': '/api/login',
                'query_params': {'username': "admin' OR '1'='1'"},
                'post_data': {'password': 'any'}
            },
            'should_detect': True
        },
        {
            'name': 'SQL Injection UNION',
            'request': {
                'path': '/api/search',
                'query_params': {'q': "' UNION SELECT password FROM users--"},
                'post_data': {}
            },
            'should_detect': True
        },
        {
            'name': 'XSS basique',
            'request': {
                'path': '/api/comment',
                'post_data': {'content': "<script>alert('xss')</script>"}
            },
            'should_detect': True
        },
        {
            'name': 'Command Injection',
            'request': {
                'path': '/api/execute',
                'post_data': {'command': '; ls -la'}
            },
            'should_detect': True
        },
        {
            'name': 'Path Traversal',
            'request': {
                'path': '/api/file',
                'query_params': {'file': '../../../etc/passwd'}
            },
            'should_detect': True
        },
        {
            'name': 'Requête normale',
            'request': {
                'path': '/api/products',
                'query_params': {'page': '1', 'search': 'laptop'},
                'post_data': {'email': 'user@example.com'}
            },
            'should_detect': False
        }
    ]
    
    print(f"\n{'='*60}")
    print("🧪 LANCEMENT DES TESTS DE DÉTECTION")
    print('='*60)
    
    results = []
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n🔍 Test {i}/{len(test_cases)}: {test_case['name']}")
        print(f"📤 Request: {test_case['request']}")
        
        try:
            result = agent.analyze_request(test_case['request'])
            print(f"📥 Result: is_malicious = {result['is_malicious']}")
            
            if result['threats_detected']:
                print("🚨 Menaces détectées:")
                for threat in result['threats_detected']:
                    print(f"   - {threat['type']} (confiance: {threat.get('confidence', 0):.2f})")
                    print(f"     Méthode: {threat.get('detection_method', 'N/A')}")
                    print(f"     Text: {threat['text'][:50]}...")
            
            # Vérification du résultat
            if result['is_malicious'] == test_case['should_detect']:
                status = "✅ SUCCÈS" if test_case['should_detect'] else "✅ CORRECT (non détecté)"
                print(f"📊 {status}")
            else:
                status = "❌ ÉCHEC - Devrait être détecté" if test_case['should_detect'] else "❌ ÉCHEC - Faux positif"
                print(f"📊 {status}")
            
            results.append({
                'test': test_case['name'],
                'expected': test_case['should_detect'],
                'actual': result['is_malicious'],
                'success': result['is_malicious'] == test_case['should_detect'],
                'threats_count': len(result['threats_detected'])
            })
            
        except Exception as e:
            print(f"💥 ERREUR pendant le test: {e}")
            results.append({
                'test': test_case['name'],
                'expected': test_case['should_detect'],
                'actual': None,
                'success': False,
                'error': str(e)
            })
    
    # Résumé final
    print(f"\n{'='*60}")
    print("📊 RÉSUMÉ DES TESTS")
    print('='*60)
    
    success_count = sum(1 for r in results if r.get('success', False))
    total_count = len(results)
    
    print(f"Tests réussis: {success_count}/{total_count} ({success_count/total_count*100:.1f}%)")
    
    for result in results:
        status = "✅" if result.get('success', False) else "❌"
        print(f"{status} {result['test']}")
        if not result.get('success', False) and 'error' in result:
            print(f"   Erreur: {result['error']}")
    
    if success_count == total_count:
        print("\n🎉 TOUS LES TESTS SONT RÉUSSIS !")
    else:
        print(f"\n⚠️  {total_count - success_count} test(s) ont échoué")

def test_model_directly():
    """Test direct du modèle MiniLM"""
    print(f"\n{'='*60}")
    print("🧠 TEST DIRECT DU MODÈLE MINILM")
    print('='*60)
    
    try:
        from sentence_transformers import SentenceTransformer
        import numpy as np
        
        model = SentenceTransformer("all-MiniLM-L6-v2")
        print("✅ Modèle MiniLM chargé directement")
        
        # Test de similarité
        texts = [
            "admin' OR '1'='1'",
            "SELECT * FROM users",
            "hello world",
            "<script>alert('xss')</script>"
        ]
        
        embeddings = model.encode(texts)
        print(f"✅ Embeddings générés: shape {embeddings.shape}")
        
        # Calcul de similarité
        from sklearn.metrics.pairwise import cosine_similarity
        similarities = cosine_similarity(embeddings)
        
        print("Matrice de similarité:")
        for i, text1 in enumerate(texts):
            for j, text2 in enumerate(texts):
                if i < j:  # Éviter les doublons
                    sim = similarities[i][j]
                    print(f"  '{text1[:20]}...' vs '{text2[:20]}...' = {sim:.3f}")
                    
    except Exception as e:
        print(f"❌ Erreur test direct modèle: {e}")

if __name__ == '__main__':
    print("🚀 DÉMARRAGE DU DÉBOGAGE DE L'AGENT DE SÉCURITÉ")
    
    # Test direct du modèle d'abord
    test_model_directly()
    
    # Tests complets de l'agent
    debug_agent()