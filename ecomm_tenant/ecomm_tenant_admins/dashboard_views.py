"""
Views for the tenant admin dashboard.
"""
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth.models import User
from django.db.models import Count, Sum
from django.utils import timezone
from datetime import timedelta

class TenantAdminDashboardView(APIView):
    """
    API view for tenant admin dashboard data.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """
        Get dashboard data for the tenant admin.
        """
        try:
            # Get tenant info from request context
            tenant = request.tenant
            
            # Get user counts
            total_users = User.objects.count()
            
            # Get recent activity (last 7 days)
            # In a real implementation, you would have an ActivityLog model
            # This is a simplified mock implementation
            recent_activity = [
                {
                    'id': 1,
                    'action': 'User login',
                    'user': 'john.doe@example.com',
                    'timestamp': (timezone.now() - timedelta(hours=2)).isoformat()
                },
                {
                    'id': 2,
                    'action': 'Invoice created',
                    'user': 'finance@example.com',
                    'timestamp': (timezone.now() - timedelta(hours=5)).isoformat()
                },
                {
                    'id': 3,
                    'action': 'New user added',
                    'user': request.user.email or request.user.username,
                    'timestamp': (timezone.now() - timedelta(days=1)).isoformat()
                }
            ]
            
            # Prepare response data
            dashboard_data = {
                'tenantInfo': {
                    'name': tenant.schema_name.upper(),
                    'status': 'Active',
                    'subscription': 'Professional Plan',
                    'usersCount': total_users,
                    'storageUsed': '2.4 GB',  # Mock data, replace with actual storage calculation
                    'storageLimit': '10 GB'   # Mock data, replace with actual plan limit
                },
                'recentActivity': recent_activity
            }
            
            return Response(dashboard_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
