# from fastapi import APIRouter, Depends, HTTPException, Query

# from controllers.results_controller import ResultsController
# from core.deps import get_current_user

# router = APIRouter(prefix="/results", tags=["Results"])


# @router.get("")
# def get_results(
#     limit:  int = Query(100, ge=1, le=500),
#     level:  str = Query(None),
#     source: str = Query(None),
#     current_user: dict = Depends(get_current_user),
# ):
#     return ResultsController.get_results(limit, level=level, source=source)


# @router.get("/{doc_type}/{doc_id}")
# def get_detail(
#     doc_type: str,
#     doc_id: str,
#     current_user: dict = Depends(get_current_user),
# ):
#     try:
#         return ResultsController.get_detail(doc_type, doc_id)
#     except ValueError as e:
#         raise HTTPException(404, str(e))