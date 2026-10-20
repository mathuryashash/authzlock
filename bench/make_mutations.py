"""Generate the mutation-benchmark patches from string edits on each app's pinned base (one-time, human-written).

  python bench/make_mutations.py   # writes bench/mutations/<app>/<name>.patch
Each mutation: (name, expected, description, file, old, new). old must occur exactly once in base.
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
APP1 = "backend/app/api/routes/items.py"
USERS1 = "backend/app/api/routes/users.py"
MODELS1 = "backend/app/models.py"
SVC2 = "todos/app/dal/db_service.py"
TODOS2 = "todos/app/api/v1/todos.py"

OWNCHK = ("    if not current_user.is_superuser and (item.owner_id != current_user.id):\n"
          "        raise HTTPException(status_code=403, detail=\"Not enough permissions\")\n")

MUTATIONS = {
    "app1": [
        ("pr-mut-update-no-owner", "FAIL", "PUT /items/{id}: ownership check dropped in an update refactor",
         [(APP1, "    item_in: ItemUpdate,\n) -> Any:\n    \"\"\"\n    Update an item.\n    \"\"\"\n    item = session.get(Item, id)\n"
                 "    if not item:\n        raise HTTPException(status_code=404, detail=\"Item not found\")\n" + OWNCHK,
           "    item_in: ItemUpdate,\n) -> Any:\n    \"\"\"\n    Update an item.\n    \"\"\"\n    item = session.get(Item, id)\n"
           "    if not item:\n        raise HTTPException(status_code=404, detail=\"Item not found\")\n")]),
        ("pr-mut-delete-no-owner", "FAIL", "DELETE /items/{id}: ownership check dropped",
         [(APP1, "    Delete an item.\n    \"\"\"\n    item = session.get(Item, id)\n"
                 "    if not item:\n        raise HTTPException(status_code=404, detail=\"Item not found\")\n" + OWNCHK,
           "    Delete an item.\n    \"\"\"\n    item = session.get(Item, id)\n"
           "    if not item:\n        raise HTTPException(status_code=404, detail=\"Item not found\")\n")]),
        ("pr-mut-list-leak", "FAIL", "GET /items/: non-superuser list query loses its owner filter (count kept)",
         [(APP1, "        statement = (\n            select(Item)\n            .where(Item.owner_id == current_user.id)\n",
           "        statement = (\n            select(Item)\n")]),
        ("pr-mut-superuser-inverted", "FAIL", "GET /items/: superuser branch condition inverted (`if not current_user.is_superuser`)",
         [(APP1, "    if current_user.is_superuser:\n        count_statement = select(func.count()).select_from(Item)\n",
           "    if not current_user.is_superuser:\n        count_statement = select(func.count()).select_from(Item)\n")]),
        ("pr-mut-users-no-role", "FAIL", "GET /users/: superuser dependency removed from the user list",
         [(USERS1, "@router.get(\n    \"/\",\n    dependencies=[Depends(get_current_active_superuser)],\n",
           "@router.get(\n    \"/\",\n")]),
        ("pr-mut-mass-assign-owner", "FAIL", "POST /items/: client may set owner_id (added to ItemCreate, honoured if sent)",
         [(MODELS1, "class ItemCreate(ItemBase):\n    pass\n",
           "class ItemCreate(ItemBase):\n    owner_id: uuid.UUID | None = None\n"),
          (APP1, "    item = Item.model_validate(item_in, update={\"owner_id\": current_user.id})\n",
           "    item = Item.model_validate(item_in, update={\"owner_id\": item_in.owner_id or current_user.id})\n")]),
        ("pr-mut-benign-helper", "PASS", "Benign refactor: item lookup + ownership check moved into one helper used by GET/PUT/DELETE",
         [(APP1, "@router.get(\"/{id}\", response_model=ItemPublic)\n",
           "def _owned_item(session: SessionDep, current_user: CurrentUser, id: uuid.UUID) -> Item:\n"
           "    item = session.get(Item, id)\n    if not item:\n        raise HTTPException(status_code=404, detail=\"Item not found\")\n"
           + OWNCHK + "    return item\n\n\n@router.get(\"/{id}\", response_model=ItemPublic)\n"),
          (APP1, "    Get item by ID.\n    \"\"\"\n    item = session.get(Item, id)\n"
                 "    if not item:\n        raise HTTPException(status_code=404, detail=\"Item not found\")\n" + OWNCHK,
           "    Get item by ID.\n    \"\"\"\n    item = _owned_item(session, current_user, id)\n")]),
        ("pr-mut-benign-order", "PASS", "Benign: GET /items/ orders by title instead of created_at for normal users",
         [(APP1, "            .where(Item.owner_id == current_user.id)\n            .order_by(col(Item.created_at).desc())\n",
           "            .where(Item.owner_id == current_user.id)\n            .order_by(col(Item.title))\n")]),
    ],
    "app2": [
        ("pr-mut-update-todo-no-owner", "FAIL", "PUT /todos/{id}: service-level owner comparison removed",
         [(SVC2, "        if not todo_to_update.created_by_id == updated_todo.created_by_id:\n"
                 "            raise UserNotAllowed('a user can not update a todo that was not created by him')\n", "")]),
        ("pr-mut-categories-list-leak", "FAIL", "GET /categories: user filter replaced by `created_by_id.isnot(None) | default` (all users' categories)",
         [(SVC2, "        user_categories_filter = Category.created_by_id == created_by_id\n        query_filter = or_(user_categories_filter, default_categories_filter)\n",
           "        user_categories_filter = Category.created_by_id.isnot(None)\n        query_filter = or_(user_categories_filter, default_categories_filter)\n")]),
        ("pr-mut-bulk-delete", "FAIL", "New DELETE /todos 'clear my todos' bulk endpoint deletes without an owner filter",
         [(TODOS2, "@router.delete(\n    '/{todo_id}',\n",
           "@router.delete('', status_code=status.HTTP_204_NO_CONTENT)\n"
           "async def clear_todos(\n    session: AsyncSession = Depends(get_async_session),\n"
           "    user: User = Depends(current_logged_user)\n) -> None:\n"
           "    from sqlalchemy import delete\n    from app.models.tables import TodoCategory\n"
           "    await session.execute(delete(TodoCategory))\n    await session.execute(delete(Todo))\n"
           "    await session.commit()\n\n\n@router.delete(\n    '/{todo_id}',\n")]),
        ("pr-mut-swap-user-source", "FAIL", "GET /todos takes the owner from an optional ?user_id= query param, falling back to the caller",
         [(TODOS2, "    user: User = Depends(current_logged_user)\n) -> Todo:\n    return await db_service.get_todos(\n        session,\n        created_by_id=user.id,\n",
           "    user: User = Depends(current_logged_user),\n    user_id: Optional[uuid.UUID] = None\n) -> Todo:\n"
           "    return await db_service.get_todos(\n        session,\n        created_by_id=user_id or user.id,\n"),
          (TODOS2, "from fastapi import APIRouter, Depends, status\n",
           "import uuid\nfrom typing import Optional\n\nfrom fastapi import APIRouter, Depends, status\n")]),
        ("pr-mut-foreign-category-link", "FAIL", "Todo create/update: category validation drops the per-user filter (link another user's category)",
         [(SVC2, "        valid_categories_filter = or_(default_categories_filter, user_categories_filter)\n        todo_categories_ids_filter",
           "        valid_categories_filter = or_(default_categories_filter, user_categories_filter, Category.id.isnot(None))\n        todo_categories_ids_filter")]),
        ("pr-mut-benign-delete-helper", "PASS", "Benign refactor: delete_todo/delete_category share one owner-checked lookup helper",
         [(SVC2, "        todo_to_delete: Optional[Todo] = await self._repo.get(\n            session,\n            table_model=Todo,\n"
                 "            query_filter=Todo.id == id_to_delete\n        )\n        if not todo_to_delete:\n"
                 "            raise ResourceNotExists(resource='todo')\n        if todo_to_delete.created_by_id != created_by_id:\n"
                 "            raise UserNotAllowed('a user can not delete a todo that was not created by him')\n",
           "        await self._owned(session, Todo, id_to_delete, created_by_id, 'todo')\n"),
          (SVC2, "    async def get_priorities(",
           "    async def _owned(self, session, model, id_, created_by_id, name):  # type: ignore[no-untyped-def]\n"
           "        row = await self._repo.get(session, table_model=model, query_filter=model.id == id_)\n"
           "        if not row:\n            raise ResourceNotExists(resource=name)\n"
           "        if row.created_by_id != created_by_id:\n"
           "            raise UserNotAllowed(f'a user can not delete a {name} that was not created by him')\n"
           "        return row\n\n    async def get_priorities(")]),
    ],
}
REPOS = {"app1": ROOT / "target", "app2": ROOT / "target2"}


def apply_edits(text_by_file: dict, edits: list) -> dict:
    out = dict(text_by_file)
    for f, old, new in edits:
        assert out[f].count(old) == 1, f"{f}: anchor found {out[f].count(old)}x: {old[:60]!r}"
        out[f] = out[f].replace(old, new)
    return out


def make(app: str, only=()) -> list:
    repo = REPOS[app]
    dest = HERE / "mutations" / app
    dest.mkdir(parents=True, exist_ok=True)
    for name, _exp, desc, edits in MUTATIONS[app]:
        if only and name not in only:
            continue
        files = {f: subprocess.run(["git", "-C", str(repo), "show", f"base:{f}"], capture_output=True, check=True)
                 .stdout.decode().replace("\r\n", "\n") for f, _, _ in edits}
        new = apply_edits(files, edits)
        wt = ROOT / ".authzlock" / "mut_wt"
        subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(wt)], capture_output=True)
        subprocess.run(["git", "-C", str(repo), "worktree", "add", "--detach", str(wt), "base"], check=True,
                       capture_output=True)
        for f, t in new.items():
            (wt / f).write_bytes(t.encode())
        subprocess.run(["git", "-C", str(wt), "add", *new], check=True)  # only the edited files (autocrlf noise)
        subprocess.run(["git", "-C", str(wt), "commit", "-qm", f"{name}: {desc}"], check=True)
        patch = subprocess.run(["git", "-C", str(wt), "format-patch", "-1", "--stdout"], capture_output=True,
                               check=True).stdout
        (dest / f"{name}.patch").write_bytes(patch)
        subprocess.run(["git", "-C", str(repo), "branch", "-f", name,
                        subprocess.run(["git", "-C", str(wt), "rev-parse", "HEAD"], capture_output=True,
                                       text=True).stdout.strip()], check=True)
        subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(wt)], check=True)
        print(app, name, len(patch), "bytes")
    return MUTATIONS[app]


if __name__ == "__main__":
    names = sys.argv[1:]  # mutation names (default: all)
    for a in MUTATIONS:
        make(a, names)
