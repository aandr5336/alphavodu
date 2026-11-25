"""Роль «API». Маршрутизація ендпоінтів каталогу ігор та заявок на прокат.

Цей файл підключається у config/urls.py під префіксом /api/v1/.
DefaultRouter сам створює стандартні адреси списку й деталі та автоматично
підхоплює @action-методи confirm і cancel із RentalViewSet.
"""
from rest_framework.routers import DefaultRouter

from .views import BoardGameViewSet, RentalViewSet

# Роутер автоматично генерує всі REST-маршрути і повертає 404 на невідомі шляхи.
router = DefaultRouter()

# Реєструємо каталог ігор: GET /api/v1/games/ та GET /api/v1/games/<id>/
router.register("games", BoardGameViewSet, basename="game")

# Реєструємо заявки: /api/v1/rentals/, /api/v1/rentals/<id>/, а також .../confirm/ і .../cancel/
router.register("rentals", RentalViewSet, basename="rental")

# Передаємо згенерований список URL-маршрутів у Django.
urlpatterns = router.urls
