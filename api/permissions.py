"""Класи прав доступу для API каталогу та заявок."""

from rest_framework import permissions


class CatalogReadOnlyPermission(permissions.BasePermission):
    """Дозволяє всім читати каталог, але забороняє змінювати його через API."""

    message = "Каталог доступний лише для читання."

    def has_permission(self, request, view):
        # SAFE_METHODS містить GET, HEAD та OPTIONS; решта методів змінює дані.
        return request.method in permissions.SAFE_METHODS


class IsOwner(permissions.BasePermission):
    """Дозволяє доступ до заявки лише її власнику.

    Для list action DRF не викликає has_object_permission для кожного рядка,
    тому RentalViewSet має також обмежувати get_queryset() поточним власником.
    """

    message = "Доступ до цієї заявки дозволений лише її власнику."

    def has_permission(self, request, view):
        # Анонімний запит відсікається до пошуку конкретної заявки.
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        # Додаткова перевірка автентифікації робить правило самодостатнім.
        return bool(
            request.user
            and request.user.is_authenticated
            and getattr(obj, "owner_id", None) == request.user.id
        )
