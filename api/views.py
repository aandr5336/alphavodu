"""Роль «API». ViewSet-и каталогу і заявок; @action confirm / cancel.

Інваріант ресурсу («коробки списані тоді й лише тоді, коли status == 'confirmed'»):
- Каталог (`BoardGameViewSet`) відкритий тільки на читання (`ReadOnlyModelViewSet`);
- Заявки (`RentalViewSet`) видимі та доступні лише аутентифікованому власнику;
- Модифікувати (`PUT`/`PATCH`) або видаляти (`DELETE`) заявку можна ЛИШЕ у стані `draft`
  (для `confirmed` та `cancelled` повертається `409 Conflict`);
- Бухгалтерію залишку в `confirm` / `cancel` атомарно виконує `api/services.py`.
"""
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from django.http import Http404
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import APIException, ValidationError as DRFValidationError
from rest_framework.response import Response

from . import permissions as app_permissions
from . import services
from .models import BoardGame, Rental
from .serializers import BoardGameSerializer, MAX_SQLITE_PK, RentalSerializer


class ConflictAPIException(APIException):
    """HTTP 409 Conflict для заборонених операцій над не-чернетками."""

    status_code = status.HTTP_409_CONFLICT
    default_detail = "Операція неможлива у поточному стані заявки."
    default_code = "conflict"


class _FallbackIsOwner(permissions.BasePermission):
    """Резервна перевірка власника на випадок, якщо api/permissions.py ще не запушено."""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        return bool(request.user and request.user.is_authenticated and obj.owner_id == request.user.id)


class SafeLookupPkMixin:
    """Перетворює нечислові або надто великі pk в URL на 404 замість 500 OverflowError."""

    def get_object(self):
        raw_pk = self.kwargs.get(self.lookup_field)
        try:
            pk_int = int(raw_pk)
        except (TypeError, ValueError):
            raise Http404
        if pk_int < 1 or pk_int > MAX_SQLITE_PK:
            raise Http404
        return super().get_object()


def _is_conflict_error(exc: Exception) -> bool:
    conflict_cls = getattr(services, "OrderConflictError", None)
    if conflict_cls is not None and isinstance(exc, conflict_cls):
        return True
    return "conflict" in exc.__class__.__name__.lower()


def _is_stock_or_validation_error(exc: Exception) -> bool:
    stock_cls = getattr(services, "InsufficientStockError", None)
    if stock_cls is not None and isinstance(exc, stock_cls):
        return True
    if isinstance(exc, (DRFValidationError, DjangoValidationError, IntegrityError, ValueError)):
        return True
    return "stock" in exc.__class__.__name__.lower()


class BoardGameViewSet(SafeLookupPkMixin, viewsets.ReadOnlyModelViewSet):
    """Каталог настільних ігор: відкритий GET без токена (рядок 1), запис заборонено."""

    queryset = BoardGame.objects.all()
    serializer_class = BoardGameSerializer

    def get_permissions(self):
        perm_cls = getattr(app_permissions, "CatalogReadOnlyPermission", permissions.AllowAny)
        return [perm_cls()]


class RentalViewSet(SafeLookupPkMixin, viewsets.ModelViewSet):
    """Заявки на прокат коробок настільних ігор."""

    serializer_class = RentalSerializer

    def get_permissions(self):
        owner_perm_cls = getattr(app_permissions, "IsOwner", _FallbackIsOwner)
        return [permissions.IsAuthenticated(), owner_perm_cls()]

    def get_queryset(self):
        # has_object_permission не викликається для списку, тому фільтруємо за власником тут (рядок 7).
        if not self.request.user or not self.request.user.is_authenticated:
            return Rental.objects.none()
        return Rental.objects.filter(owner=self.request.user).select_related("game")

    def perform_create(self, serializer):
        # Власник і початковий стан жорстко задаються сервером (рядки 11, 12).
        serializer.save(owner=self.request.user, status="draft")

    def perform_update(self, serializer):
        # Забороняємо змінювати quantity чи game у вже підтвердженій/скасованій заявці (захист інваріанта).
        with transaction.atomic():
            still_draft = Rental.objects.filter(
                pk=serializer.instance.pk,
                owner=self.request.user,
                status="draft",
            ).exists()
            if not still_draft:
                raise ConflictAPIException("Редагувати можна лише заявку у стані 'draft'.")
            serializer.save(owner=self.request.user, status="draft")

    def destroy(self, request, *args, **kwargs):
        # Спочатку get_object() перевірить токен (401) та власника (404/403 для чужої заявки — рядок 9).
        instance = self.get_object()
        with transaction.atomic():
            deleted, _ = Rental.objects.filter(
                pk=instance.pk,
                owner=request.user,
                status="draft",
            ).delete()
            if deleted == 0:
                return Response(
                    {"detail": "Видаляти можна лише чернетку ('draft'). Використайте дію cancel."},
                    status=status.HTTP_409_CONFLICT,
                )
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=["post"], url_path="confirm")
    def confirm(self, request, pk=None):
        order = self.get_object()
        try:
            updated = services.confirm_order(order.id, request.user)
        except Rental.DoesNotExist:
            raise Http404
        except Exception as exc:
            if _is_conflict_error(exc):
                return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)
            if _is_stock_or_validation_error(exc):
                return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
            raise
        return Response(self.get_serializer(updated).data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"], url_path="cancel")
    def cancel(self, request, pk=None):
        order = self.get_object()
        try:
            updated = services.cancel_order(order.id, request.user)
        except Rental.DoesNotExist:
            raise Http404
        except Exception as exc:
            if _is_conflict_error(exc):
                return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)
            if _is_stock_or_validation_error(exc):
                return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
            raise
        return Response(self.get_serializer(updated).data, status=status.HTTP_200_OK)
