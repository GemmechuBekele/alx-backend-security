from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from ratelimit.decorators import ratelimit
from django.contrib.auth import authenticate, login

@csrf_exempt
@ratelimit(key='ip', rate='5/m', method='POST', block=True)  # anonymous: 5 requests/min
def login_view(request):
    # For authenticated users, a separate rate limit will be applied below
    if request.user.is_authenticated:
        # Authenticated users get 10/min rate limiting
        ratelimit(key='ip', rate='10/m', method='POST', block=True)(lambda r: None)(request)

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return JsonResponse({'message': 'Logged in successfully'})
        return JsonResponse({'error': 'Invalid credentials'}, status=400)
    return HttpResponse("Please POST your login credentials.")

