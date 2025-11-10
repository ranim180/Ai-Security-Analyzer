
from django.http import JsonResponse
from .middleware import is_malicious

def ai_test_view(request):
    data = {
        "method": request.method,
        "headers": dict(request.headers),
        "GET_params": request.GET.dict(),
        "POST_params": request.POST.dict()
    }

    result = is_malicious(request)  # utilise ton middleware AI

    return JsonResponse({"malicious": result, "data": data})

def test_api(request):
    data = {"message": "API fonctionne !"}
    return JsonResponse(data)
