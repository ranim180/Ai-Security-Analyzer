import os

def analyze_request(request):
    data = str(request.GET.get("data", ""))

    # Simulation locale sans OpenAI
    if any(x in data.lower() for x in ["attack", "drop table", "delete", "hack"]):
        return "⚠️ Suspicious request detected!"
    else:
        return "✅ Request seems safe."