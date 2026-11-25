"""Роль «Моделі». Готує базу до атаки; запускати можна скільки завгодно разів.

    python manage.py migrate
    python manage.py seed_attack

Атакувальник клонує ваш репозиторій на тегу `attack` і запускає саме ці дві команди,
тож усе, без чого атака неможлива, має створюватися тут.
"""
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction

from api.models import BoardGame, Rental

# Ті самі паролі — у contract.json.
ATTACKERS = {"attacker1": "attack-pass-1", "attacker2": "attack-pass-2"}

# Елемент для гонки: залишок рівно 1. Те саме число в contract.json → "race_item".
RACE_ITEM_ID = 4

# id задані явно, щоб вони не змінювалися між запусками.
# (id, назва, мін. гравців, макс. гравців, коробок на полиці)
GAMES = [
    (1, "Колонізатори (Catan)", 3, 4, 50),
    (2, "Каркасон", 2, 5, 50),
    (3, "Квиток на потяг: Європа", 2, 5, 50),
    (RACE_ITEM_ID, "Дюна: Імперіум (лімітована коробка)", 1, 4, 1),
]


class Command(BaseCommand):
    help = "Акаунти attacker1/attacker2 і каталог для атаки."

    @transaction.atomic
    def handle(self, *args, **options):
        User = get_user_model()
        for username, password in ATTACKERS.items():
            user, _ = User.objects.get_or_create(username=username)
            user.set_password(password)
            user.save()

        # Спочатку видаляємо заявки, потім відновлюємо залишки: інакше лишилися б
        # confirmed-заявки, під які коробки вже не списані (порушення інваріанта).
        Rental.objects.all().delete()

        # update_or_create: немає гри з таким id — створить, є — поверне початкові значення.
        for game_id, title, min_players, max_players, available in GAMES:
            BoardGame.objects.update_or_create(
                id=game_id,
                defaults={
                    "title": title,
                    "min_players": min_players,
                    "max_players": max_players,
                    "available": available,
                },
            )
            self.stdout.write(f"id={game_id} {title}: available={available}")

        self.stdout.write(f"race_item id={RACE_ITEM_ID} (available=1)")
        self.stdout.write(self.style.SUCCESS("Готово: attacker1, attacker2, каталог."))
