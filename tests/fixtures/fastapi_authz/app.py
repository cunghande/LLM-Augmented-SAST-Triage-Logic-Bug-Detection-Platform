from fastapi import APIRouter, Depends, FastAPI


def get_current_user():
    return None


def require_admin():
    return None


def delete_user(user_id: int, current_user=Depends(get_current_user)):
    return {"deleted": user_id}


def guarded_delete(user_id: int, admin=Depends(require_admin)):
    return {"deleted": user_id}


app = FastAPI()
router = APIRouter()


@app.delete("/users/{user_id}")
def remove_user(user_id: int, current_user=Depends(get_current_user)):
    return delete_user(user_id, current_user)


@router.delete("/admin/users/{user_id}", dependencies=[Depends(require_admin)])
def admin_remove_user(user_id: int):
    return {"deleted": user_id}


@app.get("/health")
def health():
    return {"ok": True}
