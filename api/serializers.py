"""Роль «API». Серіалізатори каталогу настільних ігор і заявок на прокат.

Захищають вхідні дані до звернення в БД:
- `owner` та `status` — суворо read-only (рядки 11 і 12 карти атаки);
- `quantity` — ціле число в межах 1..100000 (рядки 13, 14, 15, захист від OverflowError у SQLite);
- `game` — перевірка існування елемента каталогу без переповнення 64-бітного ключа SQLite (рядок 16).
"""
from rest_framework import serializers

from .models import BoardGame, Rental

MAX_SQLITE_PK = (1 << 62) - 1
MAX_ORDER_QTY = 100_000


class SafeGamePrimaryKeyField(serializers.PrimaryKeyRelatedField):
    """Захищає SQLite від OverflowError (500), якщо передано гігантський id гри."""

    def to_internal_value(self, data):
        if isinstance(data, bool):
            self.fail("incorrect_type", data_type=type(data).__name__)
        try:
            pk_val = int(data)
        except (TypeError, ValueError):
            self.fail("incorrect_type", data_type=type(data).__name__)
        if pk_val < 1 or pk_val > MAX_SQLITE_PK:
            self.fail("does_not_exist", pk_value=data)
        return super().to_internal_value(pk_val)


class BoardGameSerializer(serializers.ModelSerializer):
    """Серіалізатор елемента каталогу (настільної гри). Каталог у API доступний лише на читання."""

    class Meta:
        model = BoardGame
        fields = ("id", "title", "description", "min_players", "max_players", "available")
        read_only_fields = fields


class RentalSerializer(serializers.ModelSerializer):
    """Серіалізатор заявки на прокат настільної гри."""

    game = SafeGamePrimaryKeyField(queryset=BoardGame.objects.all())
    quantity = serializers.IntegerField(min_value=1, max_value=MAX_ORDER_QTY)

    class Meta:
        model = Rental
        fields = ("id", "owner", "game", "quantity", "status", "created_at")
        # Клієнт не може підмінити власника чи одразу виставити status="confirmed" у POST/PATCH.
        read_only_fields = ("id", "owner", "status", "created_at")

    def validate_quantity(self, value):
        raw = self.initial_data.get("quantity") if isinstance(self.initial_data, dict) else None
        if isinstance(raw, bool):
            raise serializers.ValidationError("Кількість має бути цілим числом, а не логічним значенням.")
        return value
