"""Роль «API». Маршрутизація ендпоінтів каталогу ігор та заявок на прокат."""
from rest_framework.routers import DefaultRouter

from .views import BoardGameViewSet, RentalViewSet

router = DefaultRouter()
router.register("games", BoardGameViewSet, basename="game")
router.register("rentals", RentalViewSet, basename="rental")

urlpatterns = router.urls
