"""
views/analyse_views.py
======================
Déclenchement et suivi du pipeline batch.

⚠️ À COMPARER avec ton fichier existant : garde tes chemins de routes si le
frontend les appelle déjà (`/analyse/run`, `/analyse/status`…).

Le lancement est ASYNCHRONE : la requête rend la main immédiatement, le
pipeline tourne dans un thread et le front interroge /status. Un pipeline
de plusieurs minutes ne peut pas tenir dans un cycle requête/réponse.
"""
from fastapi import APIRouter, BackgroundTasks, Depends

from controllers import analyse_controller
from core.deps import get_current_user
from models.analyse_model import AnalyseStatus, AnalyseTrigger

router = APIRouter(prefix="/analyse", tags=["Analyse"])


@router.post("/run", response_model=AnalyseTrigger,
             summary="Lancer un run du pipeline")
async def run(background: BackgroundTasks,
              current_user: dict = Depends(get_current_user)) -> AnalyseTrigger:
    state = analyse_controller.get_state()
    if state["running"]:
        # 200 volontaire : ce n'est pas une erreur client, c'est un état.
        # Le front affiche « analyse déjà en cours » et bascule sur /status.
        return AnalyseTrigger(started=False, run_id=state["run_id"],
                              message="Une analyse est déjà en cours.")

    background.add_task(analyse_controller.run_analyse)
    return AnalyseTrigger(started=True, run_id=None,
                          message="Analyse lancée.")


@router.get("/status", response_model=AnalyseStatus,
            summary="État du run en cours ou du dernier run")
def status(current_user: dict = Depends(get_current_user)) -> AnalyseStatus:
    return AnalyseStatus(**analyse_controller.get_state())