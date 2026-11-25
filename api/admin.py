from django.contrib import admin

from .models import BoardGame, Rental


@admin.register(BoardGame)
class BoardGameAdmin(admin.ModelAdmin):
    # Залишок видно у списку — зручно дивитися під час атаки.
    list_display = ("id", "title", "available", "min_players", "max_players")
    search_fields = ("title",)


@admin.register(Rental)
class RentalAdmin(admin.ModelAdmin):
    list_display = ("id", "owner", "game", "quantity", "status", "created_at")
    list_filter = ("status",)
