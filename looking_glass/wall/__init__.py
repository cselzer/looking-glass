"""Request wall: wrap any WSGI or ASGI app.

    from looking_glass.wall import wall
    app = wall(app)

Call it last. Lists are checked in memory first; ASN/country lookup runs only
on a miss. Unknown visitors are allowed.
"""

from .wrapper import Decision, WallASGI, WallWSGI, wall

__all__ = ["Decision", "wall", "WallASGI", "WallWSGI"]
