import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="BoardGame",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(max_length=200)),
                ("description", models.TextField(blank=True, default="")),
                ("min_players", models.PositiveSmallIntegerField(default=2)),
                ("max_players", models.PositiveSmallIntegerField(default=4)),
                ("available", models.PositiveIntegerField(default=0)),
            ],
            options={
                "ordering": ["id"],
                "constraints": [
                    models.CheckConstraint(
                        condition=models.Q(("available__gte", 0)),
                        name="boardgame_available_non_negative",
                    )
                ],
            },
        ),
        migrations.CreateModel(
            name="Rental",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("quantity", models.PositiveIntegerField(default=1)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("draft", "Чернетка"),
                            ("confirmed", "Підтверджено"),
                            ("cancelled", "Скасовано"),
                        ],
                        db_index=True,
                        default="draft",
                        max_length=16,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "game",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="rentals",
                        to="api.boardgame",
                    ),
                ),
                (
                    "owner",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="rentals",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-id"],
                "constraints": [
                    models.CheckConstraint(
                        condition=models.Q(("quantity__gte", 1)),
                        name="rental_quantity_at_least_1",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(("status__in", ["draft", "confirmed", "cancelled"])),
                        name="rental_status_valid",
                    ),
                ],
            },
        ),
    ]
