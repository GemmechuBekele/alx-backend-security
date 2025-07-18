# ip_tracking/tasks.py

from celery import shared_task
from datetime import timedelta
from django.utils import timezone
from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ['/admin', '/login']

@shared_task
def detect_suspicious_ips():
    one_hour_ago = timezone.now() - timedelta(hours=1)

    # IPs with more than 100 requests in last hour
    high_request_ips = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(request_count=models.Count('id'))
        .filter(request_count__gt=100)
    )

    for entry in high_request_ips:
        ip = entry['ip_address']
        SuspiciousIP.objects.get_or_create(
            ip_address=ip,
            defaults={'reason': f'High request rate: {entry["request_count"]} requests in last hour'}
        )

    # IPs accessing sensitive paths
    sensitive_logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago, path__in=SENSITIVE_PATHS)
    for log in sensitive_logs:
        SuspiciousIP.objects.get_or_create(
            ip_address=log.ip_address,
            defaults={'reason': f'Accessed sensitive path: {log.path}'}
        )
