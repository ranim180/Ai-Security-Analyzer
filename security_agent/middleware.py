from .ai_agent import analyze_request

def is_malicious(request):
    return analyze_request(request)
