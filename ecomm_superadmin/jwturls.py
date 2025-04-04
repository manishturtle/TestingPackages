# accounts/urls.py
from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

# Import your authentication views here
# from .views import RegisterView, LoginView, LogoutView

urlpatterns = [
    # JWT Token endpoints
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Add your global authentication endpoints here
    # path('register/', RegisterView.as_view(), name='register'),
    # path('login/', LoginView.as_view(), name='login'),
    # path('logout/', LogoutView.as_view(), name='logout'),
    
    # Subscription plan endpoints
    # path('subscription-plans/', SubscriptionPlanListView.as_view(), name='subscription_plans'),
]
