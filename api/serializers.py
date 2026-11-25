"""Роль «API». Серіалізатори каталогу настільних ігор і заявок на прокат.

Відповідають за вхідну валідацію JSON від клієнта (до звернення в БД)
і перетворення об'єктів моделей у JSON-відповідь.
"""
from rest_framework import serializers

from .models import BoardGame, Rental

# Максимальний безпечний id для 64-бітного цілого типу в SQLite (захист від 500 OverflowError).
MAX_SQLITE_PK = (1 << 62) - 1

# Верхня межа кількості коробок у заявці (щоб гігантські числа давали 400, а не 500).
MAX_ORDER_QTY = 100_000


class SafeGamePrimaryKeyField(serializers.PrimaryKeyRelatedField):
    """Поле зовнішнього ключа на BoardGame з перевіркою типу та діапазону id гри."""

    def to_internal_value(self, data):
        """Перевіряє id гри з JSON перед тим, як робити SQL-запит у базу даних."""
        # У Python bool є підкласом int (True == 1), тому булеві значення відсікаємо явно -> 400.
        if isinstance(data, bool):
            self.fail("incorrect_type", data_type=type(data).__name__)

        # Перевіряємо, що передане значення взагалі можна перетворити на ціле число (не "abc" і не null).
        try:
            pk_val = int(data)
        except (TypeError, ValueError):
            self.fail("incorrect_type", data_type=type(data).__name__)

        # Відсікаємо <= 0 та надто великі числа ще до SQLite, повертаючи 400 ("об'єкт не існує").
        if pk_val < 1 or pk_val > MAX_SQLITE_PK:
            self.fail("does_not_exist", pk_value=data)

        # Стандартний пошук BoardGame у базі даних за перевіреним id (якщо немає -> 400).
        return super().to_internal_value(pk_val)


class BoardGameSerializer(serializers.ModelSerializer):
    """Серіалізатор каталогу настільних ігор (працює виключно на читання)."""

    class Meta:
        model = BoardGame
        # Перелік полів гри, які клієнт бачить у JSON-відповіді каталогу.
        fields = ("id", "title", "description", "min_players", "max_players", "available")
        # Робимо всі поля каталогу read-only, щоб через серіалізатор не можна було змінити залишок.
        read_only_fields = fields


class RentalSerializer(serializers.ModelSerializer):
    """Серіалізатор заявки на прокат гри та валідатор поля кількості."""

    # Перевіряє існування гри в каталозі (рядок 16 карти атаки -> 400, якщо гри не існує).
    game = SafeGamePrimaryKeyField(queryset=BoardGame.objects.all())

    # Дозволяє лише додатні цілі числа 1..100000 (відсікає -5, 0 і гігантські числа -> 400).
    # Залишок гри тут НЕ перевіряємо, бо створення заявки дає лише чернетку ("draft"),
    # яка ще не резервує коробки — реальний залишок атомарно перевірить confirm.
    quantity = serializers.IntegerField(min_value=1, max_value=MAX_ORDER_QTY)

    class Meta:
        model = Rental
        # Поля заявки, які повертаються клієнту у JSON.
        fields = ("id", "owner", "game", "quantity", "status", "created_at")
        # КРИТИЧНО (рядки 11, 12): ігноруємо owner та status із вхідного JSON,
        # щоб клієнт не міг повісити заявку на чужого юзера або створити її одразу "confirmed".
        read_only_fields = ("id", "owner", "status", "created_at")

    def validate_quantity(self, value):
        """Додатково відхиляє логічні значення true/false у полі quantity."""
        # Дістаємо сире значення з вхідного словника JSON (якщо прийшов саме об'єкт JSON).
        raw = self.initial_data.get("quantity") if isinstance(self.initial_data, dict) else None
        # Якщо клієнт надіслав {"quantity": true} — повертаємо 400 Bad Request.
        if isinstance(raw, bool):
            raise serializers.ValidationError("Кількість має бути цілим числом, а не логічним значенням.")
        return value
