from django.urls import path, include

urlpatterns = [
    path('security_agent/', include('security_agent.urls')),
]
