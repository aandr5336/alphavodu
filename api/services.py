"""Роль «Стійкість». Уся бухгалтерія ресурсу — тут, а не у views.

    def confirm_order(order_id: int, user) -> Rental: ...
    def cancel_order(order_id: int, user) -> Rental: ...

Головне правило дня: ресурс зайнятий тоді й лише тоді, коли заявка в стані
`confirmed`. Кожна функція — одна `transaction.atomic()` і умовні UPDATE
(див. регламент, етап 2). Помилки віддавайте винятками, а views перетворять
їх на 400 / 409.
"""
from django.db import IntegrityError, transaction
from django.db.models import F

from api.models import BoardGame, Rental


class OrderConflictError(Exception):
    """Заборонений перехід стану заявки (views повертають HTTP 409 Conflict)."""


class InsufficientStockError(Exception):
    """Недостатньо вільних коробок гри на складі (views повертають HTTP 400 Bad Request)."""


def confirm_order(order_id: int, user) -> Rental:
    """Підтвердити заявку користувача і атомарно списати коробки гри.

    Інваріант: BoardGame.available зменшується тільки для заявки у стані
    `confirmed`. Усі зміни відбуваються в одній транзакції через умовні UPDATE,
    тому на SQLite і PostgreSQL немає вікна гонки (TOCTOU).
    """
    try:
        with transaction.atomic():
            # Забираємо заявку цього власника разом із грою (select_related,
            # щоб у кроці 2 не робити зайовий запит до БД).
            order = Rental.objects.select_related("game").get(
                pk=order_id, owner=user
            )

            # Крок 1: атомарно змінюємо стан заявки з "draft" на "confirmed".
            # При гонці (10 одночасних confirm однієї заявки) лише один UPDATE
            # знайде рядок зі status="draft" — рівно один 200, решта отримують 409.
            updated_order = Rental.objects.filter(
                pk=order_id, owner=user, status="draft"
            ).update(status="confirmed")
            if updated_order == 0:
                raise OrderConflictError(
                    "Заявку можна підтвердити лише зі стану draft."
                )

            # Крок 2: атомарне списання залишку в БД.
            # Фільтр available__gte=quantity гарантує, що не уйдемо в мінус;
            # F() робить віднімання на стороні БД без читання-модифікації-запису у Python.
            updated_stock = BoardGame.objects.filter(
                pk=order.game_id, available__gte=order.quantity
            ).update(available=F("available") - order.quantity)
            if updated_stock == 0:
                # Виняток всередині transaction.atomic() автоматично відкочує
                # Крок 1: заявка залишається "draft", Гонка Б за останню коробку закрита.
                raise InsufficientStockError(
                    "Недостатньо вільних коробок гри в наявності."
                )

            order.refresh_from_db()
            return order
    except IntegrityError:
        # CheckConstraint (available >= 0) спрацював на рівні БД — перетворюємо
        # на biz-виняток, щоб ніколи не потрапити у 500. Транзакція вже відкочена.
        raise InsufficientStockError("Недостатньо вільних коробок гри в наявності.")


def cancel_order(order_id: int, user) -> Rental:
    """Скасувати заявку користувача та, при потребі, повернути коробки на полицю.

    Коробки повертаються рівно один раз — тільки для заявки, яка була у стані
    "confirmed". Для "draft" ресурс не зайнято, available не змінюємо.
    """
    with transaction.atomic():
        order = Rental.objects.get(pk=order_id, owner=user)

        # Варіант А: заявка була "confirmed" — скасовуємо і повертаємо залишок на полицю.
        # Умова status="confirmed" у UPDATE гарантує: при 10 одночасних cancel
        # коробки повернуться рівно один раз, решта 9 отримують 409.
        was_confirmed = Rental.objects.filter(
            pk=order_id, owner=user, status="confirmed"
        ).update(status="cancelled")
        if was_confirmed == 1:
            BoardGame.objects.filter(pk=order.game_id).update(
                available=F("available") + order.quantity
            )
            order.refresh_from_db()
            return order

        # Варіант Б: заявка була "draft" — скасовуємо, ресурс не займали, available не чіпаємо.
        was_draft = Rental.objects.filter(
            pk=order_id, owner=user, status="draft"
        ).update(status="cancelled")
        if was_draft == 1:
            order.refresh_from_db()
            return order

        # Варіант В: обидва UPDATE повернули 0 — заявка вже "cancelled".
        raise OrderConflictError("Заявка вже скасована.")
