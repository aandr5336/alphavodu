"""Роль «API». ViewSet-и каталогу настільних ігор і заявок; дії confirm / cancel.

Головне завдання цього файла — рівень HTTP:
- прийняти запит, перевірити права і знайти об'єкт;
- захистити інваріант при PUT / PATCH / DELETE (дозволені лише для чернеток "draft");
- передати confirm і cancel у services.py і перетворити бізнес-помилки на коди 400 / 409.
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
    """Власний HTTP-виняток DRF, який повертає статус 409 Conflict замість 400 чи 500."""

    status_code = status.HTTP_409_CONFLICT
    default_detail = "Операція неможлива у поточному стані заявки."
    default_code = "conflict"


class _FallbackIsOwner(permissions.BasePermission):
    """Запасний клас перевірки власника заявки (якщо в permissions.py ще немає IsOwner)."""

    def has_permission(self, request, view):
        """Відсікає анонімні запити без JWT-токена (повертає 401)."""
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        """Дозволяє доступ до конкретної заявки лише тому юзеру, хто її створив."""
        return bool(request.user and request.user.is_authenticated and obj.owner_id == request.user.id)


class SafeLookupPkMixin:
    """Міксин для безпечної перевірки id прямо в адресі URL (наприклад /rentals/abc/)."""

    def get_object(self):
        """Перевіряє id із URL до SQL-запиту, щоб сміття чи величезне число давали 404, а не 500."""
        # Беремо значення id зі шляху URL.
        raw_pk = self.kwargs.get(self.lookup_field)
        # Якщо в URL передали не число (наприклад /abc/) — одразу віддаємо 404 Not Found.
        try:
            pk_int = int(raw_pk)
        except (TypeError, ValueError):
            raise Http404
        # Якщо id <= 0 або перевищує 64-бітну межу SQLite — також віддаємо 404 (без OverflowError).
        if pk_int < 1 or pk_int > MAX_SQLITE_PK:
            raise Http404
        # Далі викликаємо стандартний пошук об'єкта DRF та перевірку прав власника.
        return super().get_object()


def _is_conflict_error(exc: Exception) -> bool:
    """Перевіряє, чи виняток із services.py означає заборонений перехід стану (-> 409)."""
    conflict_cls = getattr(services, "OrderConflictError", None)
    if conflict_cls is not None and isinstance(exc, conflict_cls):
        return True
    return "conflict" in exc.__class__.__name__.lower()


def _is_stock_or_validation_error(exc: Exception) -> bool:
    """Перевіряє, чи виняток із services.py означає нестачу коробок на складі (-> 400)."""
    stock_cls = getattr(services, "InsufficientStockError", None)
    if stock_cls is not None and isinstance(exc, stock_cls):
        return True
    if isinstance(exc, (DRFValidationError, DjangoValidationError, IntegrityError, ValueError)):
        return True
    return "stock" in exc.__class__.__name__.lower()


class BoardGameViewSet(SafeLookupPkMixin, viewsets.ReadOnlyModelViewSet):
    """Ендпоінт каталогу ігор (/api/v1/games/).

    Використовуємо саме ReadOnlyModelViewSet (а не ModelViewSet!), тому що в settings.py
    стоїть глобальний IsAuthenticatedOrReadOnly — якби тут був ModelViewSet, звичайний
    залогінений юзер зміг би змінювати залишок коробок через PATCH або видаляти ігри.
    """

    # Вибираємо всі настільні ігри з бази даних.
    queryset = BoardGame.objects.all()
    # Серіалізатор перетворює ігри у JSON.
    serializer_class = BoardGameSerializer

    def get_permissions(self):
        """Підключає CatalogReadOnlyPermission із permissions.py (відкритий GET без токена -> 200)."""
        perm_cls = getattr(app_permissions, "CatalogReadOnlyPermission", permissions.AllowAny)
        return [perm_cls()]


class RentalViewSet(SafeLookupPkMixin, viewsets.ModelViewSet):
    """Ендпоінт заявок на прокат (/api/v1/rentals/) + дії confirm і cancel."""

    serializer_class = RentalSerializer

    def get_permissions(self):
        """Вимагає вхід по JWT-токену (інакше 401) та перевіряє власника через IsOwner."""
        owner_perm_cls = getattr(app_permissions, "IsOwner", _FallbackIsOwner)
        return [permissions.IsAuthenticated(), owner_perm_cls()]

    def get_queryset(self):
        """Повертає список ТІЛЬКИ власних заявок поточного користувача.

        У DRF метод has_object_permission НЕ викликається для загального списку (GET /rentals/),
        тому фільтрація за owner обов'язково робиться саме тут.
        select_related("game") підтягує гру одним SQL JOIN (захист від проблеми N+1 запитів).
        """
        if not self.request.user or not self.request.user.is_authenticated:
            return Rental.objects.none()
        return Rental.objects.filter(owner=self.request.user).select_related("game")

    def perform_create(self, serializer):
        """При створенні заявки (POST) жорстко ставить власником автора запиту і статус 'draft'."""
        serializer.save(owner=self.request.user, status="draft")

    def perform_update(self, serializer):
        """Захищає інваріант при PUT / PATCH: редагувати дозволено ТІЛЬКИ чернетку ('draft').

        Якби ми дозволили міняти quantity або game у вже підтвердженій ('confirmed') заявці,
        юзер міг би списати 1 коробку, змінити PATCH-ем кількість на 500, зробити cancel
        і повернути на склад 500 коробок із повітря.
        """
        with transaction.atomic():
            # Перевіряємо в базі даних усередині транзакції, що заявка досі є чернеткою.
            still_draft = Rental.objects.filter(
                pk=serializer.instance.pk,
                owner=self.request.user,
                status="draft",
            ).exists()
            # Якщо заявка вже confirmed або cancelled — блокуємо редагування з кодом 409 Conflict.
            if not still_draft:
                raise ConflictAPIException("Редагувати можна лише заявку у стані 'draft'.")
            # Зберігаємо оновлені поля чернетки, залишаючи власника і статус 'draft'.
            serializer.save(owner=self.request.user, status="draft")

    def destroy(self, request, *args, **kwargs):
        """Захищає інваріант при DELETE: видаляти дозволено ТІЛЬКИ чернетку ('draft').

        Якби видалили 'confirmed'-заявку напряму, рядок заявки зник би з бази,
        а списані коробки ніколи б не повернулися на полицю в каталог.
        """
        # get_object() спочатку перевіряє токен (401) і власника (404 на чужу заявку).
        instance = self.get_object()
        with transaction.atomic():
            # Атомарно видаляємо заявку тільки якщо вона досі у стані 'draft'.
            deleted, _ = Rental.objects.filter(
                pk=instance.pk,
                owner=request.user,
                status="draft",
            ).delete()
            # Якщо видалено 0 рядків (заявка вже confirmed або cancelled) — повертаємо 409 Conflict.
            if deleted == 0:
                return Response(
                    {"detail": "Видаляти можна лише чернетку ('draft'). Використайте дію cancel."},
                    status=status.HTTP_409_CONFLICT,
                )
        # Чернетка успішно видалена (коробки вона не займала, інваріант збережено) -> 204.
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=["post"], url_path="confirm")
    def confirm(self, request, pk=None):
        """Дія POST /api/v1/rentals/<id>/confirm/ — підтверджує чернетку і списує коробки."""
        # Перевіряємо токен (401), існування заявки та що вона належить цьому юзеру (404).
        order = self.get_object()
        try:
            # Усю атомарну роботу з БД і списанням залишку делегуємо у services.confirm_order().
            updated = services.confirm_order(order.id, request.user)
        except Rental.DoesNotExist:
            raise Http404
        except Exception as exc:
            # Якщо заявка вже була confirmed або cancelled -> повертаємо 409 Conflict.
            if _is_conflict_error(exc):
                return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)
            # Якщо коробок на полиці не вистачило -> повертаємо 400 Bad Request.
            if _is_stock_or_validation_error(exc):
                return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
            raise
        # Повертаємо оновлену заявку зі статусом 'confirmed' і кодом 200 OK.
        return Response(self.get_serializer(updated).data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"], url_path="cancel")
    def cancel(self, request, pk=None):
        """Дія POST /api/v1/rentals/<id>/cancel/ — скасовує заявку (і повертає коробки, якщо була confirmed)."""
        # Перевіряємо токен (401) та власника заявки (404 на чужу заявку).
        order = self.get_object()
        try:
            # Викликаємо атомарне скасування у services.cancel_order().
            updated = services.cancel_order(order.id, request.user)
        except Rental.DoesNotExist:
            raise Http404
        except Exception as exc:
            # Якщо заявка вже була скасована ('cancelled') -> повертаємо 409 Conflict.
            if _is_conflict_error(exc):
                return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)
            if _is_stock_or_validation_error(exc):
                return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
            raise
        # Повертаємо оновлену заявку зі статусом 'cancelled' і кодом 200 OK.
        return Response(self.get_serializer(updated).data, status=status.HTTP_200_OK)
