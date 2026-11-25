"""Роль «Моделі» (Частина А): схема БД для прокату настільних ігор.

Дві моделі:
- BoardGame — каталог; `available` = скільки коробок зараз на полиці;
- Rental — заявка на прокат; автомат станів draft -> confirmed -> cancelled.

Інваріант дня: коробки списані тоді й лише тоді, коли заявка `confirmed`.
Саме тому `Rental.status` має рівно три значення, а залишок не може бути < 0.
"""
from django.conf import settings
from django.db import models


class BoardGame(models.Model):
    """Елемент каталогу: настільна гра та кількість вільних коробок."""

    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, default="")
    min_players = models.PositiveSmallIntegerField(default=2)
    max_players = models.PositiveSmallIntegerField(default=4)
    # Залишок коробок. Головний захист від «продати двічі» — умовний UPDATE
    # у services.py; CheckConstraint нижче — лише страхувальна сітка в БД.
    available = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["id"]
        constraints = [
            # Django 5.1+: аргумент називається `condition` (старий `check` застарів).
            models.CheckConstraint(
                condition=models.Q(available__gte=0),
                name="boardgame_available_non_negative",
            ),
        ]

    def __str__(self):
        return f"{self.title} (доступно: {self.available})"


class Rental(models.Model):
    """Заявка на прокат гри."""

    class Status(models.TextChoices):
        DRAFT = "draft", "Чернетка"
        CONFIRMED = "confirmed", "Підтверджено"
        CANCELLED = "cancelled", "Скасовано"

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="rentals",
    )
    # PROTECT: гру, на яку є заявки, не можна випадково видалити.
    game = models.ForeignKey(
        BoardGame, on_delete=models.PROTECT, related_name="rentals"
    )
    quantity = models.PositiveIntegerField(default=1)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.DRAFT,
        db_index=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-id"]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(quantity__gte=1),
                name="rental_quantity_at_least_1",
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=["draft", "confirmed", "cancelled"]),
                name="rental_status_valid",
            ),
        ]

    def __str__(self):
        return f"Заявка #{self.pk}: {self.game_id} x{self.quantity} [{self.status}]"
