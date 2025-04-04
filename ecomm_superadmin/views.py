"""
Views for ecomm_superadmin app.
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from django.contrib.auth import authenticate, login, get_user_model
from django.db import connection
from django.db import transaction

from .models import Tenant, User, CrmClient
from .serializers import TenantSerializer, LoginSerializer, UserSerializer, UserAdminSerializer, CrmClientSerializer

class PlatformAdminTenantView(APIView):
    """
    API endpoint that allows platform admins to manage tenants.
    Uses direct database access to avoid model field mapping issues.
    """
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    def get(self, request, format=None):
        """
        List all tenants directly from the database.
        """
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT 
                        id, schema_name, name, url_suffix, created_at, updated_at,
                        status, environment, trial_end_date, paid_until,
                        subscription_plan_id, tenant_admin_email, client_id
                    FROM ecomm_superadmin_tenants
                    ORDER BY created_at DESC
                """)
                
                # Get column names
                columns = [col[0] for col in cursor.description]
                
                # Fetch all rows
                rows = cursor.fetchall()
                
                # Convert rows to dictionaries
                tenants = []
                for row in rows:
                    tenant_dict = dict(zip(columns, row))
                    
                    # Convert datetime objects to strings for JSON serialization
                    if 'created_at' in tenant_dict and tenant_dict['created_at']:
                        tenant_dict['created_at'] = tenant_dict['created_at'].isoformat()
                    if 'updated_at' in tenant_dict and tenant_dict['updated_at']:
                        tenant_dict['updated_at'] = tenant_dict['updated_at'].isoformat()
                    if 'trial_end_date' in tenant_dict and tenant_dict['trial_end_date']:
                        tenant_dict['trial_end_date'] = tenant_dict['trial_end_date'].isoformat()
                    if 'paid_until' in tenant_dict and tenant_dict['paid_until']:
                        tenant_dict['paid_until'] = tenant_dict['paid_until'].isoformat()
                    
                    # Add subscription plan details if available
                    if tenant_dict.get('subscription_plan_id'):
                        cursor.execute("""
                            SELECT id, name, description, price, max_users, max_storage
                            FROM ecomm_superadmin_subscriptionplan
                            WHERE id = %s
                        """, [tenant_dict['subscription_plan_id']])
                        plan_columns = [col[0] for col in cursor.description]
                        plan_row = cursor.fetchone()
                        if plan_row:
                            tenant_dict['subscription_plan'] = dict(zip(plan_columns, plan_row))
                    
                    # Add client details if available
                    if tenant_dict.get('client_id'):
                        cursor.execute("""
                            SELECT id, client_name, contact_person_email
                            FROM ecomm_superadmin_crmclients
                            WHERE id = %s
                        """, [tenant_dict['client_id']])
                        client_columns = [col[0] for col in cursor.description]
                        client_row = cursor.fetchone()
                        if client_row:
                            tenant_dict['client'] = dict(zip(client_columns, client_row))
                    
                    tenants.append(tenant_dict)
                
                return Response(tenants)
        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request, format=None):
        """
        Create a new tenant using the TenantSerializer.
        """
        serializer = TenantSerializer(data=request.data)
        if serializer.is_valid():
            try:
                tenant = serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except Exception as e:
                import traceback
                traceback.print_exc()
                return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, tenant_id, format=None):
        """
        Delete a tenant by ID.
        This will follow the specific deletion flow:
        1. Delete entry from ecomm_superadmin_domain
        2. Delete entry from ecomm_superadmin_tenants
        3. Drop the schema with CASCADE
        """
        try:
            import traceback
            
            # Use a transaction to ensure atomicity
            with transaction.atomic():
                # First, check if the tenant exists using raw SQL
                with connection.cursor() as cursor:
                    cursor.execute("""
                        SELECT id, schema_name FROM ecomm_superadmin_tenants WHERE id = %s
                    """, [tenant_id])
                    
                    result = cursor.fetchone()
                    if not result:
                        return Response(
                            {"error": f"Tenant with ID {tenant_id} not found"}, 
                            status=status.HTTP_404_NOT_FOUND
                        )
                    
                    tenant_id, schema_name = result
                    
                    # 1. First delete entries from ecomm_superadmin_domain
                    try:
                        cursor.execute("""
                            DELETE FROM ecomm_superadmin_domain 
                            WHERE tenant_id = %s
                        """, [tenant_id])
                        print(f"Deleted domain entries for tenant ID {tenant_id}")
                    except Exception as domain_e:
                        print(f"Error deleting from domain table: {str(domain_e)}")
                        traceback.print_exc()
                    
                    # 2. Then delete the tenant record from ecomm_superadmin_tenants
                    cursor.execute("DELETE FROM ecomm_superadmin_tenants WHERE id = %s", [tenant_id])
                    print(f"Deleted tenant with ID {tenant_id}")
                    
                    # 3. Finally drop the schema
                    try:
                        cursor.execute(f'DROP SCHEMA IF EXISTS "{schema_name}" CASCADE')
                        print(f"Dropped schema {schema_name}")
                    except Exception as schema_e:
                        print(f"Error dropping schema: {str(schema_e)}")
                        traceback.print_exc()
            
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"error": f"Error deleting tenant: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class PlatformAdminLoginView(APIView):
    """
    API endpoint for platform admin login.
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        """
        Handle POST requests for login.
        """
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            password = serializer.validated_data.get('password')
            
            # Try to find the user by email
            try:
                user = User.objects.get(email=email)
                username = user.username
                user = authenticate(username=username, password=password)
            except User.DoesNotExist:
                user = None
            
            if user is not None and user.is_staff:
                login(request, user)
                
                # Create a simplified serializer for platform admin login
                # that doesn't rely on tenant-specific models
                user_data = {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'is_staff': user.is_staff,
                    'is_superuser': user.is_superuser,
                    'is_active': user.is_active,
                    'date_joined': user.date_joined,
                    'profile': {
                        'is_company_admin': False,
                        'is_tenant_admin': False,
                        'is_email_verified': True,
                        'is_2fa_enabled': False,
                        'needs_2fa_setup': False
                    },
                    'roles': [{'role': {'name': 'Platform Admin'}}]
                }
                
                # Generate JWT token
                from rest_framework_simplejwt.tokens import RefreshToken
                refresh = RefreshToken.for_user(user)
                
                return Response({
                    'user': user_data,
                    'token': str(refresh.access_token),
                    'refresh': str(refresh),
                    'message': 'Login successful'
                })
            
            return Response({
                'error': 'Invalid credentials or insufficient permissions'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PlatformAdminCheckUserExistsView(APIView):
    """
    API endpoint to check if a user exists.
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        """
        Check if a user exists by username or email.
        """
        email = request.data.get('email')
        
        if not email:
            return Response({
                'error': 'Email is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        user_exists = False
        is_staff = False
        
        user_exists = User.objects.filter(email=email).exists()
        if user_exists:
            user = User.objects.get(email=email)
            is_staff = user.is_staff
        
        return Response({
            'user_exists': user_exists,
            'exists': user_exists,
            'is_staff': is_staff
        })

class PlatformAdminViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows platform admins to manage users.
    
    Provides CRUD operations for User objects with appropriate permissions
    and validation for user management.
    """
    queryset = get_user_model().objects.all().order_by('-date_joined')
    serializer_class = UserAdminSerializer
    
    def get_permissions(self):
        """
        Ensure only staff users can access this viewset.
        """
        return [IsAuthenticated(), IsAdminUser()]
    
    def list(self, request, *args, **kwargs):
        """
        List all users with additional information.
        """
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        
        return Response({
            'status': 'success',
            'count': len(serializer.data),
            'data': serializer.data
        })
    
    def create(self, request, *args, **kwargs):
        """
        Create a new user with validation.
        """
        with transaction.atomic():
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            
            return Response({
                'status': 'success',
                'message': 'User created successfully',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED, headers=headers)
    
    def retrieve(self, request, *args, **kwargs):
        """
        Get a single user by ID.
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        
        return Response({
            'status': 'success',
            'data': serializer.data
        })
    
    def update(self, request, *args, **kwargs):
        """
        Update a user with validation.
        """
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        
        return Response({
            'status': 'success',
            'message': 'User updated successfully',
            'data': serializer.data
        })
    
    def destroy(self, request, *args, **kwargs):
        """
        Delete a user with confirmation.
        """
        instance = self.get_object()
        self.perform_destroy(instance)
        
        return Response({
            'status': 'success',
            'message': 'User deleted successfully'
        }, status=status.HTTP_200_OK)

class CrmClientViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows CRM clients to be viewed or edited.
    Only platform admin users have access to this endpoint.
    """
    queryset = CrmClient.objects.all()
    serializer_class = CrmClientSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    @action(detail=True, methods=['get'])
    def tenants(self, request, pk=None):
        """
        Return a list of all tenants associated with this client.
        """
        client = self.get_object()
        tenants = client.tenants.all()
        serializer = TenantSerializer(tenants, many=True)
        return Response(serializer.data)
