from datetime import datetime
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP
from django.utils import timezone
from django.core.cache import cache
from ipgeolocation import IpGeolocationAPI
from django.http import HttpResponseForbidden


class RequestLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)
        path = request.path
        RequestLog.objects.create(ip_address=ip_address, path=path)
        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class BlockIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Access denied: Your IP is blacklisted.")
        return self.get_response(request)

    def get_client_ip(self, request):
        # Use X-Forwarded-For if behind a proxy/load balancer
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

api_key = 'free'  # You may replace with a real API key from ipgeolocation.io if needed
ip_geo = IpGeolocationAPI(api_key)

class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)

        # Blocked IP logic
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Your IP is blocked.")

        # Check cache
        cache_key = f"geo:{ip_address}"
        geo_data = cache.get(cache_key)

        if not geo_data:
            geo_data = self.get_geolocation(ip_address)
            cache.set(cache_key, geo_data, timeout=60 * 60 * 24)  # Cache for 24 hours

        # Log request
        RequestLog.objects.create(
            ip_address=ip_address,
            path=request.path,
            country=geo_data.get('country_name'),
            city=geo_data.get('city')
        )

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')

    def get_geolocation(self, ip_address):
        try:
            geo_response = ip_geo.get_geolocation(ip_address)
            return {
                'country_name': geo_response.get('country_name', ''),
                'city': geo_response.get('city', '')
            }
        except Exception:
            return {'country_name': '', 'city': ''}
